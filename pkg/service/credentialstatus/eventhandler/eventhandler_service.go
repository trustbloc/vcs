/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package eventhandler -source=eventhandler_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry

package eventhandler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	defaultRepresentation = "jws"

	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignatureOfType    = "type"
)

var logger = log.New("credentialstatus-eventhandler")

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

type Config struct {
	CSLVCStore     credentialstatus.CSLVCStore
	ProfileService profileService
	KMSRegistry    kmsRegistry
	Crypto         vcCrypto
	DocumentLoader ld.DocumentLoader
}

type Service struct {
	cslStore       credentialstatus.CSLVCStore
	profileService profileService
	kmsRegistry    kmsRegistry
	crypto         vcCrypto
	documentLoader ld.DocumentLoader
}

func New(conf *Config) *Service {
	return &Service{
		cslStore:       conf.CSLVCStore,
		profileService: conf.ProfileService,
		kmsRegistry:    conf.KMSRegistry,
		crypto:         conf.Crypto,
		documentLoader: conf.DocumentLoader,
	}
}

// HandleEvent is responsible for the handling of spi.CredentialStatusStatusUpdated events.
func (s *Service) HandleEvent(ctx context.Context, event *spi.Event) error { //nolint:gocognit
	logger.Infoc(ctx, "Received event", logfields.WithEvent(event))

	if event.Type != spi.CredentialStatusStatusUpdated {
		return nil
	}

	payload := credentialstatus.UpdateCredentialStatusEventPayload{}

	jsonData, err := json.Marshal(event.Data.(map[string]interface{}))
	if err != nil {
		return err
	}

	if err := json.Unmarshal(jsonData, &payload); err != nil {
		return err
	}

	return s.handleEventPayload(ctx, payload)
}

func (s *Service) handleEventPayload(
	ctx context.Context, payload credentialstatus.UpdateCredentialStatusEventPayload) error {
	clsWrapper, err := s.getCSLVCWrapper(ctx, payload.CSLURL)
	if err != nil {
		return fmt.Errorf("get CSL VC wrapper failed: %w", err)
	}

	cs := clsWrapper.VC.Contents().Subject

	bitString, err := bitstring.DecodeBits(cs[0].CustomFields["encodedList"].(string))
	if err != nil {
		return fmt.Errorf("get encodedList from CSL customFields failed: %w", err)
	}

	if errSet := bitString.Set(payload.Index, payload.Status); errSet != nil {
		return fmt.Errorf("bitString.Set failed: %w", errSet)
	}

	cs[0].CustomFields["encodedList"], err = bitString.EncodeBits()
	if err != nil {
		return fmt.Errorf("bitString.EncodeBits failed: %w", err)
	}

	clsWrapper.VC = clsWrapper.VC.WithModifiedSubject(cs)

	signedCredentialBytes, err := s.signCSL(payload.ProfileID, payload.ProfileVersion, clsWrapper.VC)
	if err != nil {
		return fmt.Errorf("failed to sign CSL: %w", err)
	}

	vcWrapper := &credentialstatus.CSLVCWrapper{
		VCByte: signedCredentialBytes,
	}

	if err = s.cslStore.Upsert(ctx, payload.CSLURL, vcWrapper); err != nil {
		return fmt.Errorf("cslStore.Upsert failed: %w", err)
	}

	return nil
}

func (s *Service) signCSL(profileID, profileVersion string, csl *verifiable.Credential) ([]byte, error) {
	issuerProfile, err := s.profileService.GetProfile(profileID, profileVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile: %w", err)
	}

	keyManager, err := s.kmsRegistry.GetKeyManager(issuerProfile.KMSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS: %w", err)
	}

	signer := &vc.Signer{
		Format:                  issuerProfile.VCConfig.Format,
		DID:                     issuerProfile.SigningDID.DID,
		Creator:                 issuerProfile.SigningDID.Creator,
		KMSKeyID:                issuerProfile.SigningDID.KMSKeyID,
		SignatureType:           issuerProfile.VCConfig.SigningAlgorithm,
		KeyType:                 issuerProfile.VCConfig.KeyType,
		KMS:                     keyManager,
		SignatureRepresentation: issuerProfile.VCConfig.SignatureRepresentation,
		VCStatusListType:        issuerProfile.VCConfig.Status.Type,
		SDJWT:                   vc.SDJWT{Enable: false},
	}

	signOpts, err := prepareSigningOpts(signer, csl.Proofs())
	if err != nil {
		return nil, fmt.Errorf("prepareSigningOpts failed: %w", err)
	}

	signedCredential, err := s.crypto.SignCredential(signer, csl, signOpts...)
	if err != nil {
		return nil, fmt.Errorf("sign CSL failed: %w", err)
	}

	return signedCredential.MarshalJSON()
}

func (s *Service) getCSLVCWrapper(ctx context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error) {
	vcWrapper, err := s.cslStore.Get(ctx, cslURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get CSL from store: %w", err)
	}

	cslVC, err := verifiable.ParseCredential(vcWrapper.VCByte,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSL: %w", err)
	}

	vcWrapper.VC = cslVC

	return vcWrapper, nil
}

// prepareSigningOpts prepares signing opts from recently issued proof of given credential.
func prepareSigningOpts(profile *vc.Signer, proofs []verifiable.Proof) ([]vccrypto.SigningOpts, error) {
	var signingOpts []vccrypto.SigningOpts

	if len(proofs) == 0 {
		return signingOpts, nil
	}

	// pick latest proof if there are multiple
	proof := proofs[len(proofs)-1]

	representation := defaultRepresentation
	if _, ok := proof[jsonKeyProofValue]; ok {
		representation = jsonKeyProofValue
	}

	signingOpts = append(signingOpts, vccrypto.WithSigningRepresentation(representation))

	purpose, err := getStringValue(jsonKeyProofPurpose, proof)
	if err != nil {
		return nil, err
	}

	signingOpts = append(signingOpts, vccrypto.WithPurpose(purpose))

	vm, err := getStringValue(jsonKeyVerificationMethod, proof)
	if err != nil {
		return nil, err
	}

	// add verification method option only when it is not matching profile creator
	if vm != profile.Creator {
		signingOpts = append(signingOpts, vccrypto.WithVerificationMethod(vm))
	}

	signTypeName, err := getStringValue(jsonKeySignatureOfType, proof)
	if err != nil {
		return nil, err
	}

	if signTypeName != "" {
		signType, err := vcsverifiable.GetSignatureTypeByName(signTypeName)
		if err != nil {
			return nil, err
		}

		signingOpts = append(signingOpts, vccrypto.WithSignatureType(signType))
	}

	return signingOpts, nil
}

func getStringValue(key string, vMap map[string]interface{}) (string, error) {
	if val, ok := vMap[key]; ok {
		if s, ok := val.(string); ok {
			return s, nil
		}

		return "", fmt.Errorf("invalid '%s' type", key)
	}

	return "", nil
}
