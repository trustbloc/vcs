/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package github.com/trustbloc/vcs/component/credentialstatus -package credentialstatus -source=credentialstatus_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry,eventPublisher=MockEventPublisher

package credentialstatus

import (
	"context"
	"encoding/json"
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
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	cslRequestTokenName         = "csl"
	credentialStatusEventSource = "credentialstatus"
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

type eventPublisher interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type Config struct {
	HTTPClient     httpClient
	RequestTokens  map[string]string
	VDR            vdrapi.Registry
	CSLVCStore     credentialstatus.CSLVCStore
	CSLIndexStore  credentialstatus.CSLIndexStore
	VCStatusStore  vcStatusStore
	ListSize       int
	Crypto         vcCrypto
	ProfileService profileService
	KMSRegistry    kmsRegistry
	EventPublisher eventPublisher
	EventTopic     string
	DocumentLoader ld.DocumentLoader
	CMD            *cobra.Command
	ExternalURL    string
}

type Service struct {
	httpClient     httpClient
	requestTokens  map[string]string
	vdr            vdrapi.Registry
	cslVCStore     credentialstatus.CSLVCStore
	cslIndexStore  credentialstatus.CSLIndexStore
	vcStatusStore  vcStatusStore
	listSize       int
	crypto         vcCrypto
	profileService profileService
	kmsRegistry    kmsRegistry
	eventPublisher eventPublisher
	eventTopic     string
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
		cslVCStore:     config.CSLVCStore,
		cslIndexStore:  config.CSLIndexStore,
		vcStatusStore:  config.VCStatusStore,
		listSize:       config.ListSize,
		crypto:         config.Crypto,
		profileService: config.ProfileService,
		kmsRegistry:    config.KMSRegistry,
		eventPublisher: config.EventPublisher,
		eventTopic:     config.EventTopic,
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

	typedID, err := s.vcStatusStore.Get(ctx, issuerProfile.ID, params.CredentialID)
	if err != nil {
		return fmt.Errorf("vcStatusStore.Get failed: %w", err)
	}

	statusValue, err := strconv.ParseBool(params.DesiredStatus)
	if err != nil {
		return fmt.Errorf("strconv.ParseBool failed: %w", err)
	}

	err = s.updateVCStatus(ctx, typedID, issuerProfile.ID, issuerProfile.VCConfig.Status.Type, statusValue)
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

	// get latest ListID - global value among issuers.
	latestListID, err := s.cslIndexStore.GetLatestListID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	cslURL, err := s.cslVCStore.GetCSLURL(s.externalURL, profile.GroupID, latestListID)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSL wrapper URL: %w", err)
	}

	cslWrapper, err := s.getCSLIndexWrapper(ctx, cslURL)
	if err != nil {
		if errors.Is(err, credentialstatus.ErrDataNotFound) {
			cslWrapper, err = s.storeNewVCWrapperAndCreateNewIndexWrapper(ctx, signer, vcStatusProcessor, cslURL)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("failed to get CSL Index from store: %w", err)
		}
	}

	unusedStatusBitIndex, err := s.getUnusedIndex(cslWrapper.UsedIndexes)
	if err != nil {
		return nil, fmt.Errorf("getUnusedIndex failed: %w", err)
	}

	// Append unusedStatusBitIndex to the cslWrapper.UsedIndexes so marking it as "used".
	cslWrapper.UsedIndexes = append(cslWrapper.UsedIndexes, unusedStatusBitIndex)

	if err = s.cslIndexStore.Upsert(ctx, cslURL, cslWrapper); err != nil {
		return nil, fmt.Errorf("failed to store CSL Wrapper: %w", err)
	}

	// If amount of used indexes is the same as list size - update ListID,
	// so it will lead to creating new CSLIndexWrapper with empty UsedIndexes list.
	if len(cslWrapper.UsedIndexes) == s.listSize {
		if err = s.cslIndexStore.UpdateLatestListID(ctx); err != nil {
			return nil, fmt.Errorf("failed to store latest list ID in store: %w", err)
		}
	}

	statusListEntry := &credentialstatus.StatusListEntry{
		TypedID: vcStatusProcessor.CreateVCStatus(strconv.Itoa(unusedStatusBitIndex), cslURL),
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

	cslURL, err := s.cslVCStore.GetCSLURL(s.externalURL, groupID, credentialstatus.ListID(listID))
	if err != nil {
		return nil, fmt.Errorf("failed to get CSL wrapper URL: %w", err)
	}

	cslWrapper, err := s.getCSLVCWrapper(ctx, cslURL)
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

func (s *Service) getCSLIndexWrapper(ctx context.Context, cslURL string) (*credentialstatus.CSLIndexWrapper, error) {
	indexWrapper, err := s.cslIndexStore.Get(ctx, cslURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get CSLIndexWrapper from store: %w", err)
	}

	return indexWrapper, nil
}

func (s *Service) getCSLVCWrapper(ctx context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error) {
	vcWrapper, err := s.cslVCStore.Get(ctx, cslURL)
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

func (s *Service) storeNewVCWrapperAndCreateNewIndexWrapper(ctx context.Context, signer *vc.Signer,
	processor vc.StatusProcessor, cslURL string) (*credentialstatus.CSLIndexWrapper, error) {
	credentials, errCreateVC := s.createVC(cslURL, signer, processor)
	if errCreateVC != nil {
		return nil, errCreateVC
	}

	vcBytes, errMarshal := credentials.MarshalJSON()
	if errMarshal != nil {
		return nil, errMarshal
	}

	vcWrapper := &credentialstatus.CSLVCWrapper{
		VCByte:  vcBytes,
		VC:      credentials,
		Version: 1,
	}

	if err := s.cslVCStore.Upsert(ctx, cslURL, vcWrapper); err != nil {
		return nil, fmt.Errorf("failed to store CSL VC in store: %w", err)
	}

	return &credentialstatus.CSLIndexWrapper{
		UsedIndexes: nil,
		Version:     1,
	}, nil
}

// createVC signs the VC returned from VcStatusProcessor.CreateVC.
func (s *Service) createVC(vcID string,
	profile *vc.Signer, processor vc.StatusProcessor) (*verifiable.Credential, error) {
	credential, err := processor.CreateVC(vcID, s.listSize, profile)
	if err != nil {
		return nil, err
	}

	return s.crypto.SignCredential(profile, credential)
}

// updateVCStatus updates StatusListCredential associated with typedID.
func (s *Service) updateVCStatus(ctx context.Context, typedID *verifiable.TypedID, profileID string,
	vcStatusType vc.StatusType, status bool) error {
	vcStatusProcessor, err := statustype.GetVCStatusProcessor(vcStatusType)
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

	revocationListIndex, err := vcStatusProcessor.GetStatusListIndex(typedID)
	if err != nil {
		return fmt.Errorf("GetStatusListIndex failed: %w", err)
	}

	cslWrapper, err := s.getCSLVCWrapper(ctx, statusListVCID)
	if err != nil {
		return fmt.Errorf("get CSL wrapper failed: %w", err)
	}

	event, err := s.createStatusUpdatedEvent(statusListVCID, profileID, revocationListIndex, cslWrapper.Version+1, status)
	if err != nil {
		return fmt.Errorf("unable to createStatusUpdatedEvent: %w", err)
	}

	err = s.eventPublisher.Publish(ctx, s.eventTopic, event)
	if err != nil {
		return fmt.Errorf("unable to publish event %w", err)
	}

	return nil
}

func (s *Service) createStatusUpdatedEvent(cslURL, profileID string, index, version int, status bool) (*spi.Event, error) {
	ep := credentialstatus.UpdateCredentialStatusEventPayload{
		CSLURL:    cslURL,
		ProfileID: profileID,
		Index:     index,
		Status:    status,
		Version:   version,
	}

	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal UpdateCredentialStatusEventPayload: %w", err)
	}

	return spi.NewEventWithPayload(
		cslURL,
		credentialStatusEventSource,
		spi.CredentialStatusStatusUpdated,
		payload), nil
}
