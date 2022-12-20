/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package credentialstatus -source=credentialstatus_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry

package credentialstatus

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/cslstore"
)

const (
	defaultRepresentation = "jws"

	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignatureOfType    = "type"

	issuerProfiles   = "/issuer/profiles"
	credentialStatus = "/credentials/status"

	cslRequestTokenName = "csl"
)

var logger = log.New("vcs-statuslist-service")

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

type vcStore interface {
	Get(profileName, vcID string) ([]byte, error)
}

type cslStore interface {
	Upsert(cslWrapper *cslstore.CSLWrapper) error
	Get(id string) (*cslstore.CSLWrapper, error)
	CreateLatestListID(id int) error
	UpdateLatestListID(id int) error
	GetLatestListID() (int, error)
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
	CSLStore       cslStore
	VCStore        vcStore
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
	cslStore       cslStore
	vcStore        vcStore
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
		vcStore:        config.VCStore,
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
		SignatureType:           issuerProfile.VCConfig.SigningAlgorithm,
		KeyType:                 issuerProfile.VCConfig.KeyType,
		KMS:                     keyManager,
		SignatureRepresentation: issuerProfile.VCConfig.SignatureRepresentation,
		VCStatusListType:        issuerProfile.VCConfig.Status.Type,
	}

	vcBytes, err := s.vcStore.Get(issuerProfile.Name, vcID)
	if err != nil {
		return err
	}

	credential, err := verifiable.ParseCredential(vcBytes, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
	if err != nil {
		return err
	}

	statusValue, err := strconv.ParseBool(vcStatus)
	if err != nil {
		return err
	}

	return s.updateVC(credential, signer, statusValue)
}

// CreateStatusID creates issuecredential.StatusID for profileID.
func (s *Service) CreateStatusID(profileID profileapi.ID) (*issuecredential.StatusID, error) {
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
		SignatureType:           profile.VCConfig.SigningAlgorithm,
		KeyType:                 profile.VCConfig.KeyType,
		KMS:                     kms,
		Format:                  profile.VCConfig.Format,
		SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
		VCStatusListType:        profile.VCConfig.Status.Type,
	}

	vcStatusProcessor, err := GetVCStatusProcessor(signer.VCStatusListType)
	if err != nil {
		return nil, err
	}

	statusURL, err := s.getStatusListVCURL(profile.URL, profile.ID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create status URL: %w", err)
	}

	cslWrapper, err := s.getLatestCSLWrapper(signer, statusURL, vcStatusProcessor)
	if err != nil {
		return nil, err
	}

	statusListIndex := strconv.FormatInt(int64(cslWrapper.RevocationListIndex), 10)

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

	return &issuecredential.StatusID{
		VCStatus: vcStatusProcessor.CreateVCStatus(statusListIndex, cslWrapper.VC.ID),
		Context:  vcStatusProcessor.GetVCContext(),
	}, nil
}

// GetStatusListVC returns StatusListVC from underlying cslStore.
// Used for handling public HTTP requests.
func (s *Service) GetStatusListVC(profileID profileapi.ID, statusID string) (*verifiable.Credential, error) {
	profile, err := s.profileService.GetProfile(profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile: %w", err)
	}

	statusURL, err := s.getStatusListVCURL(profile.URL, profile.ID, statusID)
	if err != nil {
		return nil, fmt.Errorf("failed to get status URL: %w", err)
	}

	cslWrapper, err := s.getCSLWrapper(statusURL)
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

// getStatusListVCURL returns StatusListVC URL.
func (s *Service) getStatusListVCURL(issuerProfileURL, issuerProfileID, statusID string) (string, error) {
	return url.JoinPath(issuerProfileURL, issuerProfiles, issuerProfileID, credentialStatus, statusID)
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

func (s *Service) getCSLWrapper(id string) (*cslstore.CSLWrapper, error) {
	cslWrapper, err := s.cslStore.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	cslWrapper.VC, err = verifiable.ParseCredential(cslWrapper.VCByte, verifiable.WithDisabledProofCheck(),
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
func (s *Service) getLatestCSLWrapper(profile *vc.Signer,
	url string, processor vc.StatusProcessor) (*cslstore.CSLWrapper, error) {
	// get latest id
	id, err := s.cslStore.GetLatestListID()
	if err != nil { //nolint: nestif
		if errors.Is(err, cslstore.ErrDataNotFound) {
			if errPut := s.cslStore.CreateLatestListID(1); errPut != nil {
				return nil, fmt.Errorf("failed to store latest list ID in store: %w", errPut)
			}

			// create verifiable credential that encapsulates the revocation list
			credentials, errCreateVC := s.createVC(url+"/1", profile, processor)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := credentials.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &cslstore.CSLWrapper{VCByte: vcBytes, ListID: 1, VC: credentials}, nil
		}

		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	vcID := url + "/" + strconv.Itoa(id)

	w, err := s.getCSLWrapper(vcID)
	if err != nil { //nolint: nestif
		if errors.Is(err, cslstore.ErrDataNotFound) {
			// create verifiable credential that encapsulates the revocation list
			credentials, errCreateVC := s.createVC(vcID, profile, processor)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := credentials.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &cslstore.CSLWrapper{VCByte: vcBytes, ListID: id, VC: credentials}, nil
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
	if !strings.HasPrefix(profile.Creator, "did:key") && vm != profile.Creator {
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

// updateVC updates StatusListCredential associated with v.
// nolint: gocyclo, funlen
func (s *Service) updateVC(v *verifiable.Credential,
	profile *vc.Signer, status bool) error {
	vcStatusProcessor, err := GetVCStatusProcessor(profile.VCStatusListType)
	if err != nil {
		return err
	}
	// validate vc status
	if err = vcStatusProcessor.ValidateStatus(v.Status); err != nil {
		return err
	}

	statusListVCID, err := vcStatusProcessor.GetStatusVCURI(v.Status)
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

	revocationListIndex, err := vcStatusProcessor.GetStatusListIndex(v.Status)
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
