/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslservice

import (
	"context"
	"fmt"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/dataintegrity/models"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

//go:generate mockgen -destination cslservice_mocks_test.go -self_package mocks -package cslservice -source=cslservice.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry

const (
	defaultRepresentation = "jws"

	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignatureOfType    = "type"
)

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
	CSLStore       credentialstatus.CSLVCStore
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

func New(cfg *Config) *Service {
	return &Service{
		cslStore:       cfg.CSLStore,
		profileService: cfg.ProfileService,
		kmsRegistry:    cfg.KMSRegistry,
		crypto:         cfg.Crypto,
		documentLoader: cfg.DocumentLoader,
	}
}

func (s *Service) SignCSL(profileID, profileVersion string, csl *verifiable.Credential) ([]byte, error) {
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
		DataIntegrityProof:      issuerProfile.VCConfig.DataIntegrityProof,
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

func (s *Service) GetCSLVCWrapper(ctx context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error) {
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

func (s *Service) UpsertCSLVCWrapper(ctx context.Context, cslURL string, wrapper *credentialstatus.CSLVCWrapper) error {
	if err := s.cslStore.Upsert(ctx, cslURL, wrapper); err != nil {
		return fmt.Errorf("failed to upsert CSL: %w", err)
	}

	return nil
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

	if signTypeName != "" && signTypeName != models.DataIntegrityProof {
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
