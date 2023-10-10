/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package github.com/trustbloc/vcs/component/credentialstatus -package credentialstatus -source=credentialstatus_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry,eventPublisher=MockEventPublisher,credentialIssuanceHistoryStore=MockCredentialIssuanceHistoryStore

package credentialstatus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"

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
	credentialStatusEventSource = "source://vcs/status" //nolint:gosec
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
	Get(ctx context.Context, profileID, profileVersion, vcID string) (*verifiable.TypedID, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type eventPublisher interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type cslManager interface {
	CreateCSLEntry(
		ctx context.Context,
		profile *profileapi.Issuer,
		credentialID string,
	) (*credentialstatus.StatusListEntry, error)
}

type credentialIssuanceHistoryStore interface {
	Put(
		ctx context.Context,
		profileID profileapi.ID,
		profileVersion profileapi.Version,
		metadata *credentialstatus.CredentialMetadata) error
}

type Config struct {
	HTTPClient                     httpClient
	RequestTokens                  map[string]string
	VDR                            vdrapi.Registry
	CSLVCStore                     credentialstatus.CSLVCStore
	CSLManager                     cslManager
	VCStatusStore                  vcStatusStore
	Crypto                         vcCrypto
	ProfileService                 profileService
	KMSRegistry                    kmsRegistry
	EventPublisher                 eventPublisher
	CredentialIssuanceHistoryStore credentialIssuanceHistoryStore
	EventTopic                     string
	DocumentLoader                 ld.DocumentLoader
	CMD                            *cobra.Command
	ExternalURL                    string
}

type Service struct {
	httpClient                     httpClient
	requestTokens                  map[string]string
	vdr                            vdrapi.Registry
	cslVCStore                     credentialstatus.CSLVCStore
	cslMgr                         cslManager
	vcStatusStore                  vcStatusStore
	crypto                         vcCrypto
	profileService                 profileService
	kmsRegistry                    kmsRegistry
	eventPublisher                 eventPublisher
	credentialIssuanceHistoryStore credentialIssuanceHistoryStore
	eventTopic                     string
	documentLoader                 ld.DocumentLoader
	cmd                            *cobra.Command
	externalURL                    string
}

// New returns new Credential Status service.
func New(config *Config) (*Service, error) {
	return &Service{
		httpClient:                     config.HTTPClient,
		requestTokens:                  config.RequestTokens,
		vdr:                            config.VDR,
		cslVCStore:                     config.CSLVCStore,
		cslMgr:                         config.CSLManager,
		vcStatusStore:                  config.VCStatusStore,
		crypto:                         config.Crypto,
		profileService:                 config.ProfileService,
		kmsRegistry:                    config.KMSRegistry,
		eventPublisher:                 config.EventPublisher,
		eventTopic:                     config.EventTopic,
		credentialIssuanceHistoryStore: config.CredentialIssuanceHistoryStore,
		documentLoader:                 config.DocumentLoader,
		cmd:                            config.CMD,
		externalURL:                    config.ExternalURL,
	}, nil
}

// UpdateVCStatus fetches credential based on UpdateVCStatusParams.CredentialID
// and updates associated credentialstatus.CSL to UpdateVCStatusParams.DesiredStatus.
func (s *Service) UpdateVCStatus(ctx context.Context, params credentialstatus.UpdateVCStatusParams) error {
	logger.Debugc(ctx, "UpdateVCStatus begin",
		logfields.WithProfileID(params.ProfileID),
		logfields.WithProfileVersion(params.ProfileVersion),
		logfields.WithCredentialID(params.CredentialID))

	profile, err := s.profileService.GetProfile(params.ProfileID, params.ProfileVersion)
	if err != nil {
		return fmt.Errorf("get profile: %w", err)
	}

	if params.StatusType != profile.VCConfig.Status.Type {
		return resterr.NewValidationError(resterr.InvalidValue, "CredentialStatus.Type",
			fmt.Errorf(
				"vc status list version \"%s\" is not supported by current profile", params.StatusType))
	}

	typedID, err := s.vcStatusStore.Get(ctx, profile.ID, profile.Version, params.CredentialID)
	if err != nil {
		return fmt.Errorf("vcStatusStore.Get failed: %w", err)
	}

	statusValue, err := strconv.ParseBool(params.DesiredStatus)
	if err != nil {
		return fmt.Errorf("strconv.ParseBool failed: %w", err)
	}

	err = s.updateVCStatus(ctx, typedID, profile.ID, profile.Version, profile.VCConfig.Status.Type, statusValue)
	if err != nil {
		return fmt.Errorf("updateVCStatus failed: %w", err)
	}

	logger.Debugc(ctx, "UpdateVCStatus success")

	return nil
}

// CreateStatusListEntry creates credentialstatus.StatusListEntry for profileID.
func (s *Service) CreateStatusListEntry(
	ctx context.Context,
	profileID profileapi.ID,
	profileVersion profileapi.Version,
	credentialID string,
) (*credentialstatus.StatusListEntry, error) {
	logger.Debugc(ctx, "CreateStatusListEntry begin",
		logfields.WithProfileID(profileID),
		logfields.WithProfileVersion(profileVersion),
		logfields.WithCredentialID(credentialID))

	profile, err := s.profileService.GetProfile(profileID, profileVersion)
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}

	statusListEntry, err := s.cslMgr.CreateCSLEntry(ctx, profile, credentialID)
	if err != nil {
		return nil, fmt.Errorf("create CSL entry: %w", err)
	}

	return statusListEntry, nil
}

// StoreIssuedCredentialMetadata stores credentialstatus.CredentialMetadata for each issued credential.
func (s *Service) StoreIssuedCredentialMetadata(
	ctx context.Context,
	profileID profileapi.ID,
	profileVersion profileapi.Version,
	metadata *credentialstatus.CredentialMetadata,
) error {
	logger.Debugc(ctx, "StoreIssuedCredentialMetadata begin",
		logfields.WithProfileID(profileID),
		logfields.WithProfileVersion(profileVersion),
		logfields.WithCredentialID(metadata.CredentialID))

	err := s.credentialIssuanceHistoryStore.Put(ctx, profileID, profileVersion, metadata)
	if err != nil {
		return fmt.Errorf("storeIssuedCredentialMetadata: %w", err)
	}

	logger.Debugc(ctx, "StoreIssuedCredentialMetadata success")

	return nil
}

// GetStatusListVC returns StatusListVC (credentialstatus.CSL) from underlying cslVCStore.
// Used for handling public HTTP requests.
func (s *Service) GetStatusListVC(
	ctx context.Context, groupID profileapi.ID, listID string) (*credentialstatus.CSL, error) {
	logger.Debugc(ctx, "GetStatusListVC begin", logfields.WithProfileID(groupID), log.WithID(listID))

	cslURL, err := s.cslVCStore.GetCSLURL(s.externalURL, groupID, credentialstatus.ListID(listID))
	if err != nil {
		return nil, fmt.Errorf("get CSL wrapper URL: %w", err)
	}

	cslWrapper, err := s.getCSLVCWrapper(ctx, cslURL)
	if err != nil {
		return nil, fmt.Errorf("get CSL wrapper: %w", err)
	}

	logger.Debugc(ctx, "GetStatusListVC success")

	return cslWrapper.VC, nil
}

// Resolve resolves statusListVCURI and returns StatusListVC (credentialstatus.CSL).
// Used for credential verification.
// statusListVCURI might be either HTTP URL or DID URL.
func (s *Service) Resolve(ctx context.Context, statusListVCURI string) (*credentialstatus.CSL, error) {
	logger.Debugc(ctx, "ResolveStatusListVCURI begin", log.WithURL(statusListVCURI))
	var vcBytes []byte
	var err error
	switch {
	case strings.HasPrefix(statusListVCURI, "did:"):
		logger.Debugc(ctx, "statusListVCURI is DID document", log.WithURL(statusListVCURI))
		vcBytes, err = s.resolveDIDRelativeURL(ctx, statusListVCURI)
	default:
		logger.Debugc(ctx, "statusListVCURI is URL", log.WithURL(statusListVCURI))
		vcBytes, err = s.resolveHTTPUrl(ctx, statusListVCURI)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to resolve statusListVCURI: %w", err)
	}

	csl, err := s.parseAndVerifyVC(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("parse and verify status vc: %w", err)
	}

	logger.Debugc(ctx, "ResolveStatusListVCURI successful", log.WithURL(statusListVCURI))

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

func (s *Service) getCSLVCWrapper(ctx context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error) {
	vcWrapper, err := s.cslVCStore.Get(ctx, cslURL)
	if err != nil {
		return nil, fmt.Errorf("get CSL from store: %w", err)
	}

	cslVC, err := verifiable.ParseCredential(vcWrapper.VCByte,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("parse CSL: %w", err)
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
		return nil, fmt.Errorf("read response body for status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// updateVCStatus updates StatusListCredential associated with typedID.
func (s *Service) updateVCStatus(ctx context.Context, typedID *verifiable.TypedID, profileID, profileVersion string,
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

	event, err := s.createStatusUpdatedEvent(statusListVCID, profileID, profileVersion, revocationListIndex, status)
	if err != nil {
		return fmt.Errorf("unable to createStatusUpdatedEvent: %w", err)
	}

	err = s.eventPublisher.Publish(ctx, s.eventTopic, event)
	if err != nil {
		return fmt.Errorf("unable to publish event %w", err)
	}

	return nil
}

func (s *Service) createStatusUpdatedEvent(
	cslURL, profileID, profileVersion string, index int, status bool) (*spi.Event, error) {
	ep := credentialstatus.UpdateCredentialStatusEventPayload{
		CSLURL:         cslURL,
		ProfileID:      profileID,
		ProfileVersion: profileVersion,
		Index:          index,
		Status:         status,
	}

	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal UpdateCredentialStatusEventPayload: %w", err)
	}

	evt := spi.NewEventWithPayload(
		uuid.NewString(),
		credentialStatusEventSource,
		spi.CredentialStatusStatusUpdated,
		payload)

	// Set the routing key to the CSL URL to give the event bus a hint
	// on how/where to route the event.
	evt.RoutingKey = cslURL

	return evt, nil
}
