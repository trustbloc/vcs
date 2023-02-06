/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4ci_service_mocks_test.go -self_package mocks -package oidc4ci_test -source=oidc4ci_service.go -mock_names transactionStore=MockTransactionStore,wellKnownService=MockWellKnownService,oAuth2Client=MockOAuth2Client,httpClient=MockHTTPClient,eventService=MockEventService,pinGenerator=MockPinGenerator,claimDataStore=MockClaimDataStore,profileService=MockProfileService

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
	"golang.org/x/oauth2"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/oauth2client"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

const (
	defaultGrantType    = "authorization_code"
	defaultResponseType = "token"
	defaultScope        = "openid"
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
	GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error)
}

type oAuth2Client interface {
	Exchange(
		ctx context.Context,
		cfg oauth2.Config,
		code string,
		client *http.Client,
		opts ...oauth2client.AuthCodeOption,
	) (*oauth2.Token, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type eventService interface {
	Publish(topic string, messages ...*spi.Event) error
}

// Config holds configuration options and dependencies for Service.
type Config struct {
	TransactionStore    transactionStore
	ClaimDataStore      claimDataStore
	WellKnownService    wellKnownService
	ProfileService      profileService
	IssuerVCSPublicHost string
	OAuth2Client        oAuth2Client
	HTTPClient          httpClient
	EventService        eventService
	PinGenerator        pinGenerator
	EventTopic          string
}

// Service implements VCS credential interaction API for OIDC credential issuance.
type Service struct {
	store               transactionStore
	claimDataStore      claimDataStore
	wellKnownService    wellKnownService
	profileService      profileService
	issuerVCSPublicHost string
	oAuth2Client        oAuth2Client
	httpClient          httpClient
	eventSvc            eventService
	eventTopic          string
	pinGenerator        pinGenerator
}

// NewService returns a new Service instance.
func NewService(config *Config) (*Service, error) {
	return &Service{
		store:               config.TransactionStore,
		claimDataStore:      config.ClaimDataStore,
		wellKnownService:    config.WellKnownService,
		profileService:      config.ProfileService,
		issuerVCSPublicHost: config.IssuerVCSPublicHost,
		oAuth2Client:        config.OAuth2Client,
		httpClient:          config.HTTPClient,
		eventSvc:            config.EventService,
		eventTopic:          config.EventTopic,
		pinGenerator:        config.PinGenerator,
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
		s.sendFailedEvent(tx, err)
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
			s.sendFailedEvent(tx, err)
			return nil, err
		}
	}

	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedEvent(tx, err)
		return nil, err
	}

	if err = s.sendEvent(tx, spi.IssuerOIDCInteractionAuthorizationRequestPrepared); err != nil {
		s.sendFailedEvent(tx, err)
		return nil, err
	}

	return &PrepareClaimDataAuthorizationResponse{
		ProfileID:                          tx.ProfileID,
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

	if !strings.EqualFold(ad.CredentialType, tx.CredentialTemplate.Type) {
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

func (s *Service) ValidatePreAuthorizedCodeRequest(
	ctx context.Context,
	preAuthorizedCode string,
	pin string,
) (*Transaction, error) {
	tx, err := s.store.FindByOpState(ctx, preAuthorizedCode)
	if err != nil {
		return nil, fmt.Errorf("find tx by op state: %w", err)
	}

	newState := TransactionStatePreAuthCodeValidated
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		return nil, err
	}
	tx.State = newState

	if tx.PreAuthCode != preAuthorizedCode {
		return nil, errors.New("invalid pre-auth code")
	}

	if len(tx.UserPin) > 0 && !s.pinGenerator.Validate(tx.UserPin, pin) {
		return nil, errors.New("invalid pin")
	}

	if err = s.store.Update(ctx, tx); err != nil {
		return nil, err
	}

	if errSendEvent := s.sendEvent(tx, spi.IssuerOIDCInteractionQRScanned); errSendEvent != nil {
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
		s.sendFailedEvent(tx, ErrCredentialTemplateNotConfigured)
		return nil, ErrCredentialTemplateNotConfigured
	}

	var claimData *ClaimData

	if tx.IsPreAuthFlow {
		if claimData, err = s.claimDataStore.GetAndDelete(ctx, tx.ClaimDataID); err != nil {
			return nil, fmt.Errorf("get claim data: %w", err)
		}
	} else {
		if claimData, err = s.requestClaims(ctx, tx); err != nil {
			return nil, err
		}
	}

	// prepare credential for signing
	vc := &verifiable.Credential{
		Context: tx.CredentialTemplate.Contexts,
		ID:      uuid.New().URN(),
		Types:   []string{"VerifiableCredential", tx.CredentialTemplate.Type},
		Issuer:  verifiable.Issuer{ID: tx.DID},
		Issued:  util.NewTime(time.Now()),
	}

	if claimData != nil {
		vc.Subject = verifiable.Subject{
			ID:           req.DID,
			CustomFields: verifiable.CustomFields(*claimData),
		}
	} else {
		vc.Subject = verifiable.Subject{ID: req.DID}
	}

	var credential interface{}

	switch tx.CredentialFormat {
	case vcsverifiable.Jwt:
		claims, jwtClaimsErr := vc.JWTClaims(false)
		if jwtClaimsErr != nil {
			s.sendFailedEvent(tx, jwtClaimsErr)
			return nil, fmt.Errorf("create jwt claims: %w", jwtClaimsErr)
		}

		credential, err = claims.MarshalUnsecuredJWT()
		if err != nil {
			s.sendFailedEvent(tx, err)
			return nil, fmt.Errorf("marshal unsecured jwt: %w", err)
		}
	case vcsverifiable.Ldp:
		credential = vc
	default:
		s.sendFailedEvent(tx, ErrCredentialFormatNotSupported)
		return nil, ErrCredentialFormatNotSupported
	}

	tx.State = TransactionStateCredentialsIssued
	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedEvent(tx, err)
		return nil, err
	}

	if errSendEvent := s.sendEvent(tx, spi.IssuerOIDCInteractionSucceeded); errSendEvent != nil {
		s.sendFailedEvent(tx, errSendEvent)
		return nil, errSendEvent
	}

	return &PrepareCredentialResult{
		ProfileID:  tx.ProfileID,
		Credential: credential,
		Format:     tx.CredentialFormat,
		Retry:      false,
	}, nil
}

func (s *Service) requestClaims(ctx context.Context, tx *Transaction) (*ClaimData, error) {
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

	claimData := ClaimData(m)

	return &claimData, nil
}

func (s *Service) createEvent(
	tx *Transaction,
	eventType spi.EventType,
	e error,
) (*spi.Event, error) {
	ep := eventPayload{
		WebHook:   tx.WebHookURL,
		ProfileID: tx.ProfileID,
		OrgID:     tx.OrgID,
	}

	if e != nil {
		ep.Error = e.Error()
	}

	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	event := spi.NewEventWithPayload(uuid.NewString(), "oidc4ci", eventType, payload)
	event.TransactionID = string(tx.ID)

	return event, nil
}

func (s *Service) sendEvent(tx *Transaction, eventType spi.EventType) error {
	return s.sendEventWithError(tx, eventType, nil)
}

func (s *Service) sendEventWithError(tx *Transaction, eventType spi.EventType, e error) error {
	event, err := s.createEvent(tx, eventType, e)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(s.eventTopic, event)
}

func (s *Service) sendFailedEvent(tx *Transaction, err error) {
	e := s.sendEventWithError(tx, spi.IssuerOIDCInteractionFailed, err)
	logger.Debug("sending Failed OIDC issuer event error, ignoring..", log.WithError(e))
}
