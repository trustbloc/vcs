/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package github.com/trustbloc/vcs/component/credentialstatus -package credentialstatus -source=credentialstatus_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry

package credentialstatus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	defaultRepresentation = "jws"

	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignatureOfType    = "type"
	cslRequestTokenName       = "csl"
)

var logger = log.New("credentialstatus")

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

type vcStatusStore interface {
	Get(ctx context.Context, profileID, vcID string) (*verifiable.TypedID, error)
	Put(ctx context.Context, profileID, credentialID string, typedID *verifiable.TypedID) error
}

type profileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type Config struct {
	HTTPClient     httpClient
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
	ExternalURL    string
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
	externalURL    string
}

// New returns new Credential Status service.
func New(config *Config) (*Service, error) {
	return &Service{
		httpClient:     config.HTTPClient,
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
		externalURL:    config.ExternalURL,
	}, nil
}

// UpdateVCStatus fetches credential based on UpdateVCStatusParams.CredentialID
// and updates associated credentialstatus.CSL to UpdateVCStatusParams.DesiredStatus.
func (s *Service) UpdateVCStatus(ctx context.Context, params credentialstatus.UpdateVCStatusParams) error {
	logger.Debug("UpdateVCStatus begin",
		logfields.WithProfileID(params.ProfileID),
		logfields.WithCredentialID(params.CredentialID))

	issuerProfile, err := s.profileService.GetProfile(params.ProfileID)
	if err != nil {
		return fmt.Errorf("failed to get profile: %w", err)
	}

	if params.StatusType != issuerProfile.VCConfig.Status.Type {
		return resterr.NewValidationError(resterr.InvalidValue, "CredentialStatus.Type",
			fmt.Errorf(
				"vc status list version \"%s\" is not supported by current profile", params.StatusType))
	}

	keyManager, err := s.kmsRegistry.GetKeyManager(issuerProfile.KMSConfig)
	if err != nil {
		return fmt.Errorf("failed to get KMS: %w", err)
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

	typedID, err := s.vcStatusStore.Get(ctx, issuerProfile.ID, params.CredentialID)
	if err != nil {
		return fmt.Errorf("s.vcStatusStore.Get failed: %w", err)
	}

	statusValue, err := strconv.ParseBool(params.DesiredStatus)
	if err != nil {
		return fmt.Errorf("strconv.ParseBool failed: %w", err)
	}

	err = s.updateVCStatus(ctx, typedID, signer, statusValue)
	if err != nil {
		return fmt.Errorf("updateVCStatus failed: %w", err)
	}

	logger.Debug("UpdateVCStatus success")

	return nil
}

// CreateStatusListEntry creates issuecredential.StatusListEntry for profileID.
func (s *Service) CreateStatusListEntry(
	ctx context.Context, profileID profileapi.ID, credentialID string) (*credentialstatus.StatusListEntry, error) {

	logger.Debug("CreateStatusListEntry begin",
		logfields.WithProfileID(profileID),
		logfields.WithCredentialID(credentialID))

	profile, err := s.profileService.GetProfile(profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile: %w", err)
	}

	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS: %w", err)
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
		return nil, fmt.Errorf("failed to get VC status processor: %w", err)
	}

	cslWrapper, err := s.getLatestCSLWrapper(ctx, signer, profile, vcStatusProcessor)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest CSL wrapper: %w", err)
	}

	unusedStatusBitIndex, err := s.getUnusedIndex(cslWrapper.UsedIndexes)
	if err != nil {
		return nil, fmt.Errorf("getUnusedIndex failed: %w", err)
	}

	// Append unusedStatusBitIndex to the cslWrapper.UsedIndexes so marking it as "used".
	cslWrapper.UsedIndexes = append(cslWrapper.UsedIndexes, unusedStatusBitIndex)

	if err = s.cslStore.Upsert(ctx, cslWrapper); err != nil {
		return nil, fmt.Errorf("failed to store CSL in store: %w", err)
	}

	// If amount of used indexes is the same as list size - update ListID,
	// so it will lead to creating new CSLWrapper with empty UsedIndexes list.
	if len(cslWrapper.UsedIndexes) == s.listSize {
		if err = s.cslStore.UpdateLatestListID(ctx); err != nil {
			return nil, fmt.Errorf("failed to store latest list ID in store: %w", err)
		}
	}

	statusListEntry := &credentialstatus.StatusListEntry{
		TypedID: vcStatusProcessor.CreateVCStatus(strconv.Itoa(unusedStatusBitIndex), cslWrapper.VC.ID),
		Context: vcStatusProcessor.GetVCContext(),
	}
	// Store VC status to DB
	err = s.vcStatusStore.Put(ctx, profile.ID, credentialID, statusListEntry.TypedID)
	if err != nil {
		return nil, fmt.Errorf("failed to store credential status: %w", err)
	}

	logger.Debug("CreateStatusListEntry success")

	return statusListEntry, nil
}

func (s *Service) getUnusedIndex(usedIndexes []int) (int, error) {
	usedIndexesMap := make(map[int]struct{}, len(usedIndexes))

	for _, i := range usedIndexes {
		usedIndexesMap[i] = struct{}{}
	}

	unusedIndexes := make([]int, 0, s.listSize-len(usedIndexes))
	for i := 0; i < s.listSize; i++ {
		if _, ok := usedIndexesMap[i]; ok {
			continue
		}

		unusedIndexes = append(unusedIndexes, i)
	}

	if len(unusedIndexes) == 0 {
		return -1, errors.New("no possible unused indexes")
	}

	unusedIndexPosition := rand.Intn(len(unusedIndexes))

	return unusedIndexes[unusedIndexPosition], nil
}

// GetStatusListVC returns StatusListVC (CSL) from underlying cslStore.
// Used for handling public HTTP requests.
func (s *Service) GetStatusListVC(ctx context.Context, groupID profileapi.ID, listID string) (*verifiable.Credential, error) {
	logger.Debug("GetStatusListVC begin", logfields.WithProfileID(groupID), log.WithID(listID))

	cslURL, err := s.cslStore.GetCSLURL(s.externalURL, groupID, credentialstatus.ListID(listID))
	if err != nil {
		return nil, fmt.Errorf("failed to get CSL wrapper URL: %w", err)
	}

	cslWrapper, err := s.getCSLWrapper(ctx, cslURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get CSL wrapper from store: %w", err)
	}

	logger.Debug("GetStatusListVC success")

	return cslWrapper.VC, nil
}

// Resolve resolves statusListVCURI and returns StatusListVC (CSL).
// Used for credential verification.
// statusListVCURI might be either HTTP URL or DID URL.
func (s *Service) Resolve(ctx context.Context, statusListVCURI string) (*verifiable.Credential, error) {
	logger.Debug("ResolveStatusListVCURI begin", log.WithURL(statusListVCURI))
	var vcBytes []byte
	var err error
	switch {
	case strings.HasPrefix(statusListVCURI, "did:"):
		logger.Debug("statusListVCURI is DID document", log.WithURL(statusListVCURI))
		vcBytes, err = s.resolveDIDRelativeURL(ctx, statusListVCURI)
	default:
		logger.Debug("statusListVCURI is URL", log.WithURL(statusListVCURI))
		vcBytes, err = s.resolveHTTPUrl(ctx, statusListVCURI)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to resolve statusListVCURI: %w", err)
	}

	csl, err := s.parseAndVerifyVC(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify status vc: %w", err)
	}

	logger.Debug("ResolveStatusListVCURI successful", log.WithURL(statusListVCURI))

	return csl, nil
}

func (s *Service) resolveHTTPUrl(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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

func (s *Service) getCSLWrapper(ctx context.Context, cslURL string) (*credentialstatus.CSLWrapper, error) {
	cslWrapper, err := s.cslStore.Get(ctx, cslURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get CSL from store: %w", err)
	}

	cslWrapper.VC, err = verifiable.ParseCredential(cslWrapper.VCByte,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSL: %w", err)
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
func (s *Service) getLatestCSLWrapper(ctx context.Context, signer *vc.Signer, profile *profileapi.Issuer,
	processor vc.StatusProcessor) (*credentialstatus.CSLWrapper, error) {
	// get latest ListID - global value among issuers.
	latestListID, err := s.cslStore.GetLatestListID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	cslURL, err := s.cslStore.GetCSLURL(s.externalURL, profile.GroupID, latestListID)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSL wrapper URL: %w", err)
	}

	w, err := s.getCSLWrapper(ctx, cslURL)
	if err != nil { //nolint: nestif
		if errors.Is(err, credentialstatus.ErrDataNotFound) {
			// create credentialstatus.CSL
			credentials, errCreateVC := s.createVC(cslURL, signer, processor)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := credentials.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &credentialstatus.CSLWrapper{
				VCByte:      vcBytes,
				UsedIndexes: nil,
				VC:          credentials,
			}, nil
		}

		return nil, fmt.Errorf("failed to get CSL from store: %w", err)
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
func (s *Service) updateVCStatus(ctx context.Context, typedID *verifiable.TypedID,
	profile *vc.Signer, status bool) error {
	vcStatusProcessor, err := statustype.GetVCStatusProcessor(profile.VCStatusListType)
	if err != nil {
		return fmt.Errorf("get VC status processor failed: %w", err)
	}
	// validate vc status
	if err = vcStatusProcessor.ValidateStatus(typedID); err != nil {
		return fmt.Errorf("validate VC status failed: %w", err)
	}

	statusListVCID, err := vcStatusProcessor.GetStatusVCURI(typedID)
	if err != nil {
		return fmt.Errorf("get status VC URI failed: %w", err)
	}

	cslWrapper, err := s.getCSLWrapper(ctx, statusListVCID)
	if err != nil {
		return fmt.Errorf("get CSL wrapper failed: %w", err)
	}

	signOpts, err := prepareSigningOpts(profile, cslWrapper.VC.Proofs)
	if err != nil {
		return fmt.Errorf("prepareSigningOpts failed: %w", err)
	}

	cs, ok := cslWrapper.VC.Subject.([]verifiable.Subject)
	if !ok {
		return fmt.Errorf("failed to cast VC subject")
	}

	bitString, err := bitstring.DecodeBits(cs[0].CustomFields["encodedList"].(string))
	if err != nil {
		return fmt.Errorf("get encodedList from CSL customFields failed: %w", err)
	}

	revocationListIndex, err := vcStatusProcessor.GetStatusListIndex(typedID)
	if err != nil {
		return fmt.Errorf("GetStatusListIndex failed: %w", err)
	}

	if errSet := bitString.Set(revocationListIndex, status); errSet != nil {
		return fmt.Errorf("bitString.Set failed: %w", errSet)
	}

	cs[0].CustomFields["encodedList"], err = bitString.EncodeBits()
	if err != nil {
		return fmt.Errorf("bitString.EncodeBits failed: %w", err)
	}

	// remove all proofs because we are updating VC
	cslWrapper.VC.Proofs = nil

	signedCredential, err := s.crypto.SignCredential(profile, cslWrapper.VC, signOpts...)
	if err != nil {
		return fmt.Errorf("sign CSL failed: %w", err)
	}

	signedCredentialBytes, err := signedCredential.MarshalJSON()
	if err != nil {
		return fmt.Errorf("CSL marshal failed: %w", err)
	}

	cslWrapper.VCByte = signedCredentialBytes

	if err = s.cslStore.Upsert(ctx, cslWrapper); err != nil {
		return fmt.Errorf("cslStore.Upsert failed: %w", err)
	}

	return nil
}
