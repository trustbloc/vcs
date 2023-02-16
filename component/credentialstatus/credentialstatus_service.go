/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package github.com/trustbloc/vcs/component/credentialstatus -package credentialstatus -source=credentialstatus_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry

package credentialstatus

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vcs/pkg/doc/vc"

	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

const (
	defaultRepresentation = "jws"

	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignatureOfType    = "type"
	cslRequestTokenName       = "csl"
)

var logger = log.New("vcs-statuslist-service")

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

type vcStatusStore interface {
	Get(profileID, vcID string) (*verifiable.TypedID, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type Config struct {
	TLSConfig      *tls.Config
	RequestTokens  map[string]string
	VDR            vdrapi.Registry
	CSLStore       credentialstatus.CSLStore
	VCStatusStore  vcStatusStore
	ListSize       int
	Crypto         vcCrypto
	ProfileService profileService
	KMSRegistry    kmsRegistry
	DocumentLoader ld.DocumentLoader
	CMD            *cobra.Command
}

type Service struct {
	httpClient     httpClient
	requestTokens  map[string]string
	vdr            vdrapi.Registry
	cslStore       credentialstatus.CSLStore
	vcStatusStore  vcStatusStore
	listSize       int
	crypto         vcCrypto
	profileService profileService
	kmsRegistry    kmsRegistry
	documentLoader ld.DocumentLoader
	cmd            *cobra.Command
}

// New returns new Credential Status service.
func New(config *Config) (*Service, error) {
	return &Service{
		httpClient:     &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:  config.RequestTokens,
		vdr:            config.VDR,
		cslStore:       config.CSLStore,
		vcStatusStore:  config.VCStatusStore,
		listSize:       config.ListSize,
		crypto:         config.Crypto,
		profileService: config.ProfileService,
		kmsRegistry:    config.KMSRegistry,
		documentLoader: config.DocumentLoader,
		cmd:            config.CMD,
	}, nil
}

// UpdateVCStatus fetches credential based on vcID and updates associated StatusListCredential to vcStatus.
func (s *Service) UpdateVCStatus(profileID profileapi.ID, vcID, vcStatus string, vcStatusType vc.StatusType) error {
	issuerProfile, err := s.profileService.GetProfile(profileID)
	if err != nil {
		return fmt.Errorf("failed to get profile: %w", err)
	}

	if vcStatusType != issuerProfile.VCConfig.Status.Type {
		return resterr.NewValidationError(resterr.InvalidValue, "CredentialStatus.Type",
			fmt.Errorf(
				"vc status list version %s not supported by current profile", vcStatusType))
	}

	keyManager, err := s.kmsRegistry.GetKeyManager(issuerProfile.KMSConfig)
	if err != nil {
		return fmt.Errorf("failed to get kms: %w", err)
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

	typedID, err := s.vcStatusStore.Get(issuerProfile.ID, vcID)
	if err != nil {
		return err
	}

	statusValue, err := strconv.ParseBool(vcStatus)
	if err != nil {
		return err
	}

	return s.updateVCStatus(typedID, signer, statusValue)
}

// CreateStatusListEntry creates issuecredential.StatusListEntry for profileID.
func (s *Service) CreateStatusListEntry(profileID profileapi.ID) (*issuecredential.StatusListEntry, error) {
	profile, err := s.profileService.GetProfile(profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile: %w", err)
	}

	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kms: %w", err)
	}

	signer := &vc.Signer{
		DID:                     profile.SigningDID.DID,
		Creator:                 profile.SigningDID.Creator,
		KMSKeyID:                profile.SigningDID.KMSKeyID,
		SignatureType:           profile.VCConfig.SigningAlgorithm,
		KeyType:                 profile.VCConfig.KeyType,
		KMS:                     kms,
		Format:                  profile.VCConfig.Format,
		SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
		VCStatusListType:        profile.VCConfig.Status.Type,
		SDJWT:                   vc.SDJWT{Enable: false},
	}

	vcStatusProcessor, err := statustype.GetVCStatusProcessor(signer.VCStatusListType)
	if err != nil {
		return nil, err
	}

	cslWrapper, err := s.getLatestCSLWrapper(signer, profile, vcStatusProcessor)
	if err != nil {
		return nil, err
	}

	statusBitIndex := strconv.FormatInt(int64(cslWrapper.RevocationListIndex), 10)

	cslWrapper.Size++
	cslWrapper.RevocationListIndex++

	if err = s.cslStore.Upsert(cslWrapper); err != nil {
		return nil, fmt.Errorf("failed to store csl in store: %w", err)
	}

	if cslWrapper.Size == s.listSize {
		id := cslWrapper.ListID

		id++

		if err = s.cslStore.UpdateLatestListID(id); err != nil {
			return nil, fmt.Errorf("failed to store latest list ID in store: %w", err)
		}
	}

	return &issuecredential.StatusListEntry{
		TypedID: vcStatusProcessor.CreateVCStatus(statusBitIndex, cslWrapper.VC.ID),
		Context: vcStatusProcessor.GetVCContext(),
	}, nil
}

// GetStatusListVC returns StatusListVC from underlying cslStore.
// Used for handling public HTTP requests.
func (s *Service) GetStatusListVC(profileID profileapi.ID, statusID string) (*verifiable.Credential, error) {
	profile, err := s.profileService.GetProfile(profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile: %w", err)
	}

	cslURL, err := s.cslStore.GetCSLURL(profile.URL, profile.ID, statusID)
	if err != nil {
		return nil, fmt.Errorf("failed to get CSL wrapper URL: %w", err)
	}

	cslWrapper, err := s.getCSLWrapper(cslURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get revocationListVC from store: %w", err)
	}

	return cslWrapper.VC, nil
}

// Resolve resolves statusListVCURI and returns StatusListVC.
// Used for credential verification.
// statusListVCURI might be either HTTP URL or DID URL.
func (s *Service) Resolve(statusListVCURI string) (*verifiable.Credential, error) {
	var vcBytes []byte
	var err error
	switch {
	case strings.HasPrefix(statusListVCURI, "did:"):
		vcBytes, err = s.resolveDIDRelativeURL(statusListVCURI)
	default:
		vcBytes, err = s.resolveHTTPUrl(statusListVCURI)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to resolve statusListVCURI: %w", err)
	}

	statusListVC, err := s.parseAndVerifyVC(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify status vc: %w", err)
	}

	return statusListVC, nil
}

func (s *Service) resolveHTTPUrl(url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.sendHTTPRequest(req, http.StatusOK, s.requestTokens[cslRequestTokenName])
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *Service) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	return verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
	)
}

func (s *Service) getCSLWrapper(cslURL string) (*credentialstatus.CSLWrapper, error) {
	cslWrapper, err := s.cslStore.Get(cslURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	cslWrapper.VC, err = verifiable.ParseCredential(cslWrapper.VCByte,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
	if err != nil {
		return nil, err
	}

	return cslWrapper, nil
}

func (s *Service) sendHTTPRequest(req *http.Request, status int, token string) ([]byte, error) {
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warn("failed to close response body")
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warn("Unable to read response", log.WithHTTPStatus(resp.StatusCode), log.WithError(err))
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("failed to read response body for status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

//nolint:gocognit
func (s *Service) getLatestCSLWrapper(signer *vc.Signer, profile *profileapi.Issuer,
	processor vc.StatusProcessor) (*credentialstatus.CSLWrapper, error) {
	// get latest id
	latestListID, err := s.cslStore.GetLatestListID()
	if err != nil {
		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	cslURL, err := s.cslStore.GetCSLURL(profile.URL, profile.ID, strconv.Itoa(latestListID))
	if err != nil {
		return nil, fmt.Errorf("failed to create CSL wrapper URL: %w", err)
	}

	w, err := s.getCSLWrapper(cslURL)
	if err != nil { //nolint: nestif
		if errors.Is(err, credentialstatus.ErrDataNotFound) {
			// create verifiable credential that encapsulates the revocation list
			credentials, errCreateVC := s.createVC(cslURL, signer, processor)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := credentials.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &credentialstatus.CSLWrapper{
				VCByte:              vcBytes,
				Size:                0,
				RevocationListIndex: 0,
				ListID:              latestListID,
				VC:                  credentials,
			}, nil
		}

		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	return w, nil
}

// createVC signs the VC returned from VcStatusProcessor.CreateVC.
func (s *Service) createVC(vcID string,
	profile *vc.Signer, processor vc.StatusProcessor) (*verifiable.Credential, error) {
	credential, err := processor.CreateVC(vcID, s.listSize, profile)
	if err != nil {
		return nil, err
	}

	signOpts, err := prepareSigningOpts(profile, credential.Proofs)
	if err != nil {
		return nil, err
	}

	return s.crypto.SignCredential(profile, credential, signOpts...)
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

// updateVCStatus updates StatusListCredential associated with typedID.
// nolint: gocyclo, funlen
func (s *Service) updateVCStatus(typedID *verifiable.TypedID,
	profile *vc.Signer, status bool) error {
	vcStatusProcessor, err := statustype.GetVCStatusProcessor(profile.VCStatusListType)
	if err != nil {
		return err
	}
	// validate vc status
	if err = vcStatusProcessor.ValidateStatus(typedID); err != nil {
		return err
	}

	statusListVCID, err := vcStatusProcessor.GetStatusVCURI(typedID)
	if err != nil {
		return err
	}

	cslWrapper, err := s.getCSLWrapper(statusListVCID)
	if err != nil {
		return err
	}

	signOpts, err := prepareSigningOpts(profile, cslWrapper.VC.Proofs)
	if err != nil {
		return err
	}

	cs, ok := cslWrapper.VC.Subject.([]verifiable.Subject)
	if !ok {
		return fmt.Errorf("failed to cast vc subject")
	}

	bitString, err := bitstring.DecodeBits(cs[0].CustomFields["encodedList"].(string))
	if err != nil {
		return err
	}

	revocationListIndex, err := vcStatusProcessor.GetStatusListIndex(typedID)
	if err != nil {
		return err
	}

	if errSet := bitString.Set(revocationListIndex, status); errSet != nil {
		return errSet
	}

	cs[0].CustomFields["encodedList"], err = bitString.EncodeBits()
	if err != nil {
		return err
	}

	// remove all proofs because we are updating VC
	cslWrapper.VC.Proofs = nil

	signedCredential, err := s.crypto.SignCredential(profile, cslWrapper.VC, signOpts...)
	if err != nil {
		return err
	}

	signedCredentialBytes, err := signedCredential.MarshalJSON()
	if err != nil {
		return err
	}

	cslWrapper.VCByte = signedCredentialBytes

	return s.cslStore.Upsert(cslWrapper)
}
