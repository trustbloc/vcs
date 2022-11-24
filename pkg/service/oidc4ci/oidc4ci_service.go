/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4ci_service_mocks_test.go -self_package mocks -package oidc4ci_test -source=oidc4ci_service.go -mock_names transactionStore=MockTransactionStore,wellKnownService=MockWellKnownService,oAuth2Client=MockOAuth2Client,httpClient=MockHTTPClient,eventService=MockEventService

package oidc4ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/trustbloc/vcs/pkg/event/spi"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/logutil-go/pkg/log"
	"golang.org/x/oauth2"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/oauth2client"
)

const (
	defaultGrantType    = "authorization_code"
	defaultResponseType = "token"
	defaultScope        = "openid"
)

var logger = log.New("oidc4ci")

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

type wellKnownService interface {
	GetOIDCConfiguration(
		ctx context.Context,
		url string,
	) (*OIDCConfiguration, error)
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
	WellKnownService    wellKnownService
	IssuerVCSPublicHost string
	OAuth2Client        oAuth2Client
	HTTPClient          httpClient
	EventService        eventService
}

// Service implements VCS credential interaction API for OIDC credential issuance.
type Service struct {
	store               transactionStore
	wellKnownService    wellKnownService
	issuerVCSPublicHost string
	oAuth2Client        oAuth2Client
	httpClient          httpClient
	eventSvc            eventService
}

// NewService returns a new Service instance.
func NewService(config *Config) (*Service, error) {
	return &Service{
		store:               config.TransactionStore,
		wellKnownService:    config.WellKnownService,
		issuerVCSPublicHost: config.IssuerVCSPublicHost,
		oAuth2Client:        config.OAuth2Client,
		httpClient:          config.HTTPClient,
		eventSvc:            config.EventService,
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
		AuthorizationParameters: &OAuthParameters{
			ClientID:     tx.ClientID,
			ClientSecret: tx.ClientSecret,
			ResponseType: req.ResponseType,
			Scope:        tx.ClientScope,
		},
		AuthorizationEndpoint:              tx.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: tx.PushedAuthorizationRequestEndpoint,
		TxID:                               tx.ID,
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

	if tx.PreAuthCode != preAuthorizedCode || (tx.UserPinRequired && len(pin) == 0) {
		// TODO: Add proper pin validation
		return nil, errors.New("invalid auth credentials")
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

	var claimData map[string]interface{}
	if tx.IsPreAuthFlow {
		claimData = tx.ClaimData
	} else {
		r, requestErr := s.requestClaims(ctx, tx)
		if requestErr != nil {
			return nil, requestErr
		}
		claimData = r
	}

	// prepare credential for signing
	vc := &verifiable.Credential{
		Context: tx.CredentialTemplate.Contexts,
		ID:      uuid.New().URN(),
		Types:   []string{"VerifiableCredential", tx.CredentialTemplate.Type},
		Issuer:  verifiable.Issuer{ID: tx.CredentialTemplate.Issuer},
		Subject: verifiable.Subject{
			ID:           req.DID,
			CustomFields: claimData,
		},
		Issued: util.NewTime(time.Now()),
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

	var claimData map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&claimData); err != nil {
		return nil, fmt.Errorf("decode claim data: %w", err)
	}

	return claimData, nil
}

func (s *Service) createEvent(
	tx *Transaction,
	eventType spi.EventType,
	e error,
) (*spi.Event, error) {
	ep := eventPayload{
		TxID:    string(tx.ID),
		WebHook: tx.WebHookURL,
	}

	if e != nil {
		ep.Error = e.Error()
	}

	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	return spi.NewEvent(uuid.NewString(), "oidc4ci", eventType, payload), nil
}

func (s *Service) sendEvent(tx *Transaction, eventType spi.EventType) error {
	return s.sendEventWithError(tx, eventType, nil)
}

func (s *Service) sendEventWithError(tx *Transaction, eventType spi.EventType, e error) error {
	event, err := s.createEvent(tx, eventType, e)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(spi.IssuerEventTopic, event)
}

func (s *Service) sendFailedEvent(tx *Transaction, err error) {
	e := s.sendEventWithError(tx, spi.IssuerOIDCInteractionFailed, err)
	logger.Debug("sending Failed OIDC issuer event error, ignoring..", log.WithError(e))
}
