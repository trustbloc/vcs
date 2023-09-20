/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4ci_service_mocks_test.go -self_package mocks -package oidc4ci_test -source=oidc4ci_service.go -mock_names transactionStore=MockTransactionStore,wellKnownService=MockWellKnownService,eventService=MockEventService,pinGenerator=MockPinGenerator,credentialOfferReferenceStore=MockCredentialOfferReferenceStore,claimDataStore=MockClaimDataStore,profileService=MockProfileService,dataProtector=MockDataProtector,kmsRegistry=MockKMSRegistry,cryptoJWTSigner=MockCryptoJWTSigner

package oidc4ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	util "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
)

const (
	defaultGrantType    = "authorization_code"
	defaultResponseType = "token"
	defaultCtx          = "https://www.w3.org/2018/credentials/v1"
)

var logger = log.New("oidc4ci")

type pinGenerator interface {
	Generate(challenge string) string
	Validate(challenge string, userInput string) bool
}

type transactionStore interface {
	Create(
		ctx context.Context,
		data *TransactionData,
		params ...func(insertOptions *InsertOptions),
	) (*Transaction, error)

	Get(
		ctx context.Context,
		txID TxID,
	) (*Transaction, error)

	FindByOpState(
		ctx context.Context,
		opState string,
	) (*Transaction, error)

	Update(
		ctx context.Context,
		tx *Transaction,
	) error
}

type claimDataStore interface {
	Create(ctx context.Context, data *ClaimData) (string, error)
	GetAndDelete(ctx context.Context, id string) (*ClaimData, error)
}

type wellKnownService interface {
	GetOIDCConfiguration(
		ctx context.Context,
		url string,
	) (*OIDCConfiguration, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error)
}

type eventService interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type credentialOfferReferenceStore interface {
	Create(
		ctx context.Context,
		credentialOffer *CredentialOfferResponse,
	) (string, error)
	CreateJWT(
		ctx context.Context,
		credentialOfferJWT string,
	) (string, error)
}

type dataProtector interface {
	Encrypt(ctx context.Context, msg []byte) (*dataprotect.EncryptedData, error)
	Decrypt(ctx context.Context, encryptedData *dataprotect.EncryptedData) ([]byte, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type cryptoJWTSigner interface {
	NewJWTSigned(claims interface{}, signerData *vc.Signer) (string, error)
}

// Config holds configuration options and dependencies for Service.
type Config struct {
	TransactionStore              transactionStore
	ClaimDataStore                claimDataStore
	WellKnownService              wellKnownService
	ProfileService                profileService
	IssuerVCSPublicHost           string
	HTTPClient                    *http.Client
	EventService                  eventService
	PinGenerator                  pinGenerator
	EventTopic                    string
	PreAuthCodeTTL                int32
	CredentialOfferReferenceStore credentialOfferReferenceStore // optional
	DataProtector                 dataProtector
	KMSRegistry                   kmsRegistry
	CryptoJWTSigner               cryptoJWTSigner
}

// Service implements VCS credential interaction API for OIDC credential issuance.
type Service struct {
	store                         transactionStore
	claimDataStore                claimDataStore
	wellKnownService              wellKnownService
	profileService                profileService
	issuerVCSPublicHost           string
	httpClient                    *http.Client
	eventSvc                      eventService
	eventTopic                    string
	pinGenerator                  pinGenerator
	preAuthCodeTTL                int32
	credentialOfferReferenceStore credentialOfferReferenceStore // optional
	dataProtector                 dataProtector
	kmsRegistry                   kmsRegistry
	cryptoJWTSigner               cryptoJWTSigner
}

// NewService returns a new Service instance.
func NewService(config *Config) (*Service, error) {
	return &Service{
		store:                         config.TransactionStore,
		claimDataStore:                config.ClaimDataStore,
		wellKnownService:              config.WellKnownService,
		profileService:                config.ProfileService,
		issuerVCSPublicHost:           config.IssuerVCSPublicHost,
		httpClient:                    config.HTTPClient,
		eventSvc:                      config.EventService,
		eventTopic:                    config.EventTopic,
		pinGenerator:                  config.PinGenerator,
		preAuthCodeTTL:                config.PreAuthCodeTTL,
		credentialOfferReferenceStore: config.CredentialOfferReferenceStore,
		dataProtector:                 config.DataProtector,
		kmsRegistry:                   config.KMSRegistry,
		cryptoJWTSigner:               config.CryptoJWTSigner,
	}, nil
}

func (s *Service) PushAuthorizationDetails(
	ctx context.Context,
	opState string,
	ad *AuthorizationDetails,
) error {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return fmt.Errorf("find tx by op state: %w", err)
	}

	return s.updateAuthorizationDetails(ctx, ad, tx)
}

func (s *Service) checkScopes(reqScopes []string, txScopes []string) error {
	isScopeValid := true

	for _, scope := range reqScopes {
		found := false

		for _, v := range txScopes {
			if v == scope {
				found = true
				break
			}
		}

		if !found {
			isScopeValid = false
			break
		}
	}

	if !isScopeValid {
		return ErrInvalidScope
	}

	return nil
}

func (s *Service) PrepareClaimDataAuthorizationRequest(
	ctx context.Context,
	req *PrepareClaimDataAuthorizationRequest,
) (*PrepareClaimDataAuthorizationResponse, error) {
	tx, err := s.store.FindByOpState(ctx, req.OpState)

	if err != nil && errors.Is(err, ErrDataNotFound) {
		// process wallet initiated flow
		walletFlowResp, walletFlowErr := s.prepareClaimDataAuthorizationRequestWalletInitiated(
			ctx,
			req.Scope,
			ExtractIssuerURL(req.OpState),
		)
		if walletFlowErr != nil && errors.Is(walletFlowErr, ErrInvalidIssuerURL) { // not wallet-initiated flow
			return nil, err
		}

		return walletFlowResp, walletFlowErr
	}

	if err != nil {
		return nil, err
	}

	newState := TransactionStateAwaitingIssuerOIDCAuthorization
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return nil, err
	}
	tx.State = newState

	if req.ResponseType != tx.ResponseType {
		return nil, ErrResponseTypeMismatch
	}

	if err = s.checkScopes(req.Scope, tx.Scope); err != nil {
		return nil, err
	}

	if req.AuthorizationDetails != nil {
		if err = s.updateAuthorizationDetails(ctx, req.AuthorizationDetails, tx); err != nil {
			s.sendFailedTransactionEvent(ctx, tx, err)
			return nil, err
		}
	}

	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return nil, err
	}

	if err = s.sendTransactionEvent(ctx, tx, spi.IssuerOIDCInteractionAuthorizationRequestPrepared); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return nil, err
	}

	return &PrepareClaimDataAuthorizationResponse{
		ProfileID:                          tx.ProfileID,
		ProfileVersion:                     tx.ProfileVersion,
		TxID:                               tx.ID,
		ResponseType:                       tx.ResponseType,
		Scope:                              tx.ClientScope,
		AuthorizationEndpoint:              tx.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: tx.PushedAuthorizationRequestEndpoint,
	}, nil
}

func (s *Service) prepareClaimDataAuthorizationRequestWalletInitiated(
	ctx context.Context,
	requestScopes []string,
	issuerURL string,
) (*PrepareClaimDataAuthorizationResponse, error) {
	sp := strings.Split(issuerURL, "/")
	if len(sp) < WalletInitFlowClaimExpectedMatchCount {
		logger.Error("invalid issuer url for wallet initiated flow", log.WithURL(issuerURL))
		return nil, ErrInvalidIssuerURL
	}

	profileID, profileVersion := sp[len(sp)-2], sp[len(sp)-1]

	profile, err := s.profileService.GetProfile(profileID, profileVersion)
	if err != nil {
		return nil, fmt.Errorf("wallet initiated flow get profile: %w", err)
	}

	if profile.OIDCConfig == nil || !profile.OIDCConfig.WalletInitiatedAuthFlowSupported {
		return nil, errors.New("wallet initiated auth flow is not supported for current profile")
	}
	if profile.OIDCConfig.ClaimsEndpoint == "" {
		return nil, errors.New("empty claims endpoint for profile")
	}
	if len(profile.CredentialTemplates) == 0 {
		return nil, errors.New("no credential templates configured")
	}

	oidcConfig, err := s.wellKnownService.GetOIDCConfiguration(ctx, profile.OIDCConfig.IssuerWellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("wallet initiated flow get oidc config: %w", err)
	}

	event := eventPayload{
		WebHook:             profile.WebHook,
		ProfileID:           profileID,
		ProfileVersion:      profileVersion,
		OrgID:               profile.OrganizationID,
		WalletInitiatedFlow: true,
	}

	if err = s.sendEvent(ctx, spi.IssuerOIDCInteractionAuthorizationRequestPrepared, "", event); err != nil {
		event.Error = err.Error()
		s.sendFailedEvent(ctx, "", event)
		return nil, err
	}

	return &PrepareClaimDataAuthorizationResponse{
		WalletInitiatedFlow: &common.WalletInitiatedFlowData{
			ProfileId:            profileID,
			ProfileVersion:       profileVersion,
			ClaimEndpoint:        profile.OIDCConfig.ClaimsEndpoint,
			CredentialTemplateId: profile.CredentialTemplates[0].ID,
			OpState:              uuid.NewString(),
			Scopes:               &requestScopes,
		},
		ProfileID:             profileID,
		ProfileVersion:        profileVersion,
		Scope:                 requestScopes,
		AuthorizationEndpoint: oidcConfig.AuthorizationEndpoint,
	}, nil
}

func (s *Service) updateAuthorizationDetails(ctx context.Context, ad *AuthorizationDetails, tx *Transaction) error {
	if tx.CredentialTemplate == nil {
		return ErrCredentialTemplateNotConfigured
	}

	targetType := ad.Types[len(ad.Types)-1]
	if !strings.EqualFold(targetType, tx.CredentialTemplate.Type) {
		return ErrCredentialTypeNotSupported
	}

	if ad.Format != "" && ad.Format != tx.CredentialFormat {
		return ErrCredentialFormatNotSupported
	}

	tx.AuthorizationDetails = ad

	if err := s.store.Update(ctx, tx); err != nil {
		return fmt.Errorf("update tx: %w", err)
	}

	return nil
}

func (s *Service) ValidatePreAuthorizedCodeRequest( //nolint:gocognit,nolintlint
	ctx context.Context,
	preAuthorizedCode string,
	pin string,
	clientID string,
) (*Transaction, error) {
	tx, err := s.store.FindByOpState(ctx, preAuthorizedCode)
	if err != nil {
		return nil, resterr.NewCustomError(resterr.OIDCTxNotFound, fmt.Errorf("find tx by op state: %w", err))
	}

	if len(pin) > 0 && len(tx.UserPin) == 0 {
		return nil, resterr.NewCustomError(resterr.OIDCPreAuthorizeDoesNotExpectPin,
			fmt.Errorf("server does not expect pin"))
	}

	if len(pin) == 0 && len(tx.UserPin) > 0 {
		return nil, resterr.NewCustomError(resterr.OIDCPreAuthorizeExpectPin,
			fmt.Errorf("server expects user pin"))
	}

	if clientID == "" {
		var profile *profileapi.Issuer

		profile, err = s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
		if err != nil {
			return nil, err
		}

		// profile.OIDCConfig is not required for pre-auth flow, so no specific error for this case.
		if profile.OIDCConfig != nil && !profile.OIDCConfig.PreAuthorizedGrantAnonymousAccessSupported {
			return nil, resterr.NewCustomError(resterr.OIDCPreAuthorizeInvalidClientID,
				fmt.Errorf("issuer does not accept Token Request with a Pre-Authorized Code but without a client_id"))
		}
	}

	newState := TransactionStatePreAuthCodeValidated
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		return nil, err
	}
	tx.State = newState

	if tx.PreAuthCodeExpiresAt.UTC().Before(time.Now().UTC()) {
		return nil, resterr.NewCustomError(resterr.OIDCTxNotFound, fmt.Errorf("invalid pre-authorization code"))
	}

	if tx.PreAuthCode != preAuthorizedCode {
		return nil, resterr.NewCustomError(resterr.OIDCTxNotFound, fmt.Errorf("invalid pre-authorization code"))
	}

	if len(tx.UserPin) > 0 && !s.pinGenerator.Validate(tx.UserPin, pin) {
		return nil, resterr.NewCustomError(resterr.OIDCPreAuthorizeInvalidPin, fmt.Errorf("invalid pin"))
	}

	if err = s.store.Update(ctx, tx); err != nil {
		return nil, err
	}

	if errSendEvent := s.sendTransactionEvent(ctx, tx, spi.IssuerOIDCInteractionQRScanned); errSendEvent != nil {
		return nil, errSendEvent
	}

	return tx, nil
}

func (s *Service) PrepareCredential(
	ctx context.Context,
	req *PrepareCredential,
) (*PrepareCredentialResult, error) {
	tx, err := s.store.Get(ctx, req.TxID)
	if err != nil {
		return nil, fmt.Errorf("get tx: %w", err)
	}

	if tx.CredentialTemplate == nil {
		s.sendFailedTransactionEvent(ctx, tx, ErrCredentialTemplateNotConfigured)
		return nil, resterr.NewCustomError(resterr.OIDCCredentialTypeNotSupported, ErrCredentialTemplateNotConfigured)
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		return nil, err
	}

	var staticURLPathChunk string
	if profile.OIDCConfig != nil && profile.OIDCConfig.SignedIssuerMetadataSupported {
		staticURLPathChunk = "/static"
	}

	expectedAudience := fmt.Sprintf("%v/issuer%s/%s/%s",
		s.issuerVCSPublicHost, staticURLPathChunk, tx.ProfileID, tx.ProfileVersion)

	if req.AudienceClaim == "" || req.AudienceClaim != expectedAudience {
		return nil, resterr.NewValidationError(resterr.InvalidOrMissingProofOIDCErr, req.AudienceClaim,
			errors.New("invalid aud"))
	}

	claimData, err := s.getClaimsData(ctx, tx)
	if err != nil {
		return nil, err
	}

	contexts := tx.CredentialTemplate.Contexts
	if len(contexts) == 0 {
		contexts = []string{defaultCtx}
	}

	// prepare credential for signing
	vc := &verifiable.Credential{
		Context:      contexts,
		ID:           uuid.New().URN(),
		Types:        []string{"VerifiableCredential", tx.CredentialTemplate.Type},
		Issuer:       verifiable.Issuer{ID: tx.DID},
		Issued:       util.NewTime(time.Now()),
		CustomFields: map[string]interface{}{},
	}

	if tx.CredentialDescription != "" {
		vc.CustomFields["description"] = tx.CredentialDescription
	}
	if tx.CredentialName != "" {
		vc.CustomFields["name"] = tx.CredentialName
	}

	if tx.CredentialExpiresAt != nil {
		vc.Expired = util.NewTime(*tx.CredentialExpiresAt)
	}

	if claimData != nil {
		vc.Subject = verifiable.Subject{
			ID:           req.DID,
			CustomFields: claimData,
		}
	} else {
		vc.Subject = verifiable.Subject{ID: req.DID}
	}

	tx.State = TransactionStateCredentialsIssued
	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return nil, err
	}

	if errSendEvent := s.sendTransactionEvent(ctx, tx, spi.IssuerOIDCInteractionSucceeded); errSendEvent != nil {
		s.sendFailedTransactionEvent(ctx, tx, errSendEvent)
		return nil, errSendEvent
	}

	return &PrepareCredentialResult{
		ProfileID:               tx.ProfileID,
		ProfileVersion:          tx.ProfileVersion,
		Credential:              vc,
		Format:                  tx.CredentialFormat,
		OidcFormat:              tx.OIDCCredentialFormat,
		Retry:                   false,
		EnforceStrictValidation: tx.CredentialTemplate.Checks.Strict,
		CredentialTemplate:      tx.CredentialTemplate,
	}, nil
}

func (s *Service) getClaimsData(
	ctx context.Context,
	tx *Transaction,
) (map[string]interface{}, error) {
	if !tx.IsPreAuthFlow {
		return s.requestClaims(ctx, tx)
	}

	tempClaimData, claimDataErr := s.claimDataStore.GetAndDelete(ctx, tx.ClaimDataID)
	if claimDataErr != nil {
		return nil, fmt.Errorf("get claim data: %w", claimDataErr)
	}

	decryptedClaims, decryptErr := s.DecryptClaims(ctx, tempClaimData)
	if decryptErr != nil {
		return nil, decryptErr
	}

	return decryptedClaims, nil
}

func (s *Service) requestClaims(ctx context.Context, tx *Transaction) (map[string]interface{}, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, tx.ClaimEndpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	r.Header.Set("Authorization", "Bearer "+tx.IssuerToken)

	resp, err := s.httpClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, ioErr := io.ReadAll(resp.Body)
		if ioErr != nil {
			log.ReadRequestBodyError(logger, ioErr)
		} else {
			logger.Errorc(ctx, "Failed to fetch claims data",
				log.WithURL(tx.ClaimEndpoint),
				log.WithHTTPStatus(resp.StatusCode),
				log.WithResponse(b),
			)
		}

		return nil, fmt.Errorf("claim endpoint returned status code %d", resp.StatusCode)
	}

	var m map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode claim data: %w", err)
	}

	return m, nil
}

func (s *Service) createEvent(
	eventType spi.EventType,
	transactionID TxID,
	ep eventPayload,
) (*spi.Event, error) {
	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	event := spi.NewEventWithPayload(uuid.NewString(), "source://vcs/issuer", eventType, payload)
	event.TransactionID = string(transactionID)

	return event, nil
}

func (s *Service) sendEvent(
	ctx context.Context,
	eventType spi.EventType,
	transactionID TxID,
	ep eventPayload) error {
	event, err := s.createEvent(eventType, transactionID, ep)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
}

func (s *Service) sendFailedEvent(
	ctx context.Context,
	transactionID TxID,
	ep eventPayload) {
	e := s.sendEvent(ctx, spi.IssuerOIDCInteractionFailed, transactionID, ep)
	logger.Debugc(ctx, "sending Failed OIDC issuer event error, ignoring..", log.WithError(e))
}

func (s *Service) sendTransactionEvent(
	ctx context.Context,
	tx *Transaction,
	eventType spi.EventType,
) error {
	return s.sendEvent(ctx, eventType, tx.ID, eventPayload{
		WebHook:             tx.WebHookURL,
		ProfileID:           tx.ProfileID,
		ProfileVersion:      tx.ProfileVersion,
		OrgID:               tx.OrgID,
		WalletInitiatedFlow: tx.WalletInitiatedIssuance,
	})
}

func (s *Service) sendFailedTransactionEvent(
	ctx context.Context,
	tx *Transaction,
	e error,
) {
	s.sendFailedEvent(ctx, tx.ID, eventPayload{
		WebHook:        tx.WebHookURL,
		ProfileID:      tx.ProfileID,
		ProfileVersion: tx.ProfileVersion,
		OrgID:          tx.OrgID,
		Error:          e.Error(),
	})
}
