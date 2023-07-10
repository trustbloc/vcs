/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4ci_service_mocks_test.go -self_package mocks -package oidc4ci_test -source=oidc4ci_service.go -mock_names transactionStore=MockTransactionStore,wellKnownService=MockWellKnownService,eventService=MockEventService,pinGenerator=MockPinGenerator,credentialOfferReferenceStore=MockCredentialOfferReferenceStore,claimDataStore=MockClaimDataStore,profileService=MockProfileService,dataProtector=MockDataProtector

package oidc4ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
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
		request *CredentialOfferResponse,
	) (string, error)
}

type dataProtector interface {
	Encrypt(ctx context.Context, msg []byte) (*dataprotect.EncryptedData, error)
	Decrypt(ctx context.Context, encryptedData *dataprotect.EncryptedData) ([]byte, error)
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

	if err = s.updateAuthorizationDetails(ctx, ad, tx); err != nil {
		return err
	}

	return nil
}

func (s *Service) PrepareClaimDataAuthorizationRequest(
	ctx context.Context,
	req *PrepareClaimDataAuthorizationRequest,
) (*PrepareClaimDataAuthorizationResponse, error) {
	tx, err := s.store.FindByOpState(ctx, req.OpState)
	if err != nil {
		return nil, fmt.Errorf("find tx by op state: %w", err)
	}

	newState := TransactionStateAwaitingIssuerOIDCAuthorization
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		s.sendFailedEvent(ctx, tx, err)
		return nil, err
	}
	tx.State = newState

	if req.ResponseType != tx.ResponseType {
		return nil, ErrResponseTypeMismatch
	}

	isScopeValid := true

	for _, scope := range req.Scope {
		found := false

		for _, v := range tx.Scope {
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
		return nil, ErrInvalidScope
	}

	if req.AuthorizationDetails != nil {
		if err = s.updateAuthorizationDetails(ctx, req.AuthorizationDetails, tx); err != nil {
			s.sendFailedEvent(ctx, tx, err)
			return nil, err
		}
	}

	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedEvent(ctx, tx, err)
		return nil, err
	}

	if err = s.sendEvent(ctx, tx, spi.IssuerOIDCInteractionAuthorizationRequestPrepared); err != nil {
		s.sendFailedEvent(ctx, tx, err)
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

	if errSendEvent := s.sendEvent(ctx, tx, spi.IssuerOIDCInteractionQRScanned); errSendEvent != nil {
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
		s.sendFailedEvent(ctx, tx, ErrCredentialTemplateNotConfigured)
		return nil, resterr.NewCustomError(resterr.OIDCCredentialTypeNotSupported, ErrCredentialTemplateNotConfigured)
	}

	expectedAudience := fmt.Sprintf("%v/issuer/%s/%s", s.issuerVCSPublicHost, tx.ProfileID, tx.ProfileVersion)

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
		s.sendFailedEvent(ctx, tx, err)
		return nil, err
	}

	if errSendEvent := s.sendEvent(ctx, tx, spi.IssuerOIDCInteractionSucceeded); errSendEvent != nil {
		s.sendFailedEvent(ctx, tx, errSendEvent)
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
		return nil, fmt.Errorf("claim endpoint returned status code %d", resp.StatusCode)
	}

	var m map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode claim data: %w", err)
	}

	return m, nil
}

func (s *Service) createEvent(
	tx *Transaction,
	eventType spi.EventType,
	e error,
) (*spi.Event, error) {
	ep := eventPayload{
		WebHook:        tx.WebHookURL,
		ProfileID:      tx.ProfileID,
		ProfileVersion: tx.ProfileVersion,
		OrgID:          tx.OrgID,
	}

	if e != nil {
		ep.Error = e.Error()
	}

	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	event := spi.NewEventWithPayload(uuid.NewString(), "source://vcs/issuer", eventType, payload)
	event.TransactionID = string(tx.ID)

	return event, nil
}

func (s *Service) sendEvent(ctx context.Context, tx *Transaction, eventType spi.EventType) error {
	return s.sendEventWithError(ctx, tx, eventType, nil)
}

func (s *Service) sendEventWithError(ctx context.Context, tx *Transaction, eventType spi.EventType, e error) error {
	event, err := s.createEvent(tx, eventType, e)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
}

func (s *Service) sendFailedEvent(ctx context.Context, tx *Transaction, err error) {
	e := s.sendEventWithError(ctx, tx, spi.IssuerOIDCInteractionFailed, err)
	logger.Debugc(ctx, "sending Failed OIDC issuer event error, ignoring..", log.WithError(e))
}
