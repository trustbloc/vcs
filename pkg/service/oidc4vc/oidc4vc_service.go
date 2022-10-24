/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4vc_service_mocks_test.go -self_package mocks -package oidc4vc_test -source=oidc4vc_service.go -mock_names transactionStore=MockTransactionStore,httpClient=MockHTTPClient,privateAPIClient=MockPrivateAPIClient,wellKnownService=MockWellKnownService

package oidc4vc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/privateapi"
	"github.com/trustbloc/vcs/internal/pkg/log"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

const (
	defaultGrantType    = "authorization_code"
	defaultResponseType = "token"
	defaultScope        = "openid"
	defaultCallbackPath = "/callback"
)

var logger = log.New("oidc4vc")

type transactionStore interface {
	Create(ctx context.Context, data *TransactionData, params ...func(insertOptions *InsertOptions)) (*Transaction, error)
	FindByOpState(ctx context.Context, opState string) (*Transaction, error)
	Update(ctx context.Context, tx *Transaction) error
}

type wellKnownService[T any] interface {
	GetWellKnownConfiguration(
		ctx context.Context,
		url string,
	) (*T, error)
}

type privateAPIClient interface {
	PrepareClaimDataAuthZ(
		ctx context.Context,
		req *privateapi.PrepareClaimDataAuthZRequest,
	) (*privateapi.PrepareClaimDataAuthZResponse, error)
}

// Config holds configuration options and dependencies for Service.
type Config struct {
	TransactionStore       transactionStore
	IssuerVCSPublicHost    string
	PrivateAPIClient       privateAPIClient
	IssuerWellKnownService wellKnownService[IssuerWellKnown]
	ClientWellKnownService wellKnownService[ClientWellKnown]
}

// Service implements OIDC for VC issuance functionality.
type Service struct {
	store                  transactionStore
	issuerVCSPublicHost    string
	privateAPIClient       privateAPIClient
	issuerWellKnownService wellKnownService[IssuerWellKnown]
	clientWellKnownService wellKnownService[ClientWellKnown]
}

// NewService returns a new Service instance.
func NewService(config *Config) (*Service, error) {
	return &Service{
		store:                  config.TransactionStore,
		privateAPIClient:       config.PrivateAPIClient,
		issuerWellKnownService: config.IssuerWellKnownService,
		clientWellKnownService: config.ClientWellKnownService,
		issuerVCSPublicHost:    config.IssuerVCSPublicHost,
	}, nil
}

// InitiateInteraction creates credential issuance transaction and builds initiate issuance URL.
func (s *Service) InitiateInteraction(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	profile *profileapi.Issuer,
) (*InitiateIssuanceResponse, error) {
	template, err := findCredentialTemplate(profile.CredentialTemplates, req.CredentialTemplateID)
	if err != nil {
		return nil, err
	}

	data := &TransactionData{
		OIDC4VCConfig:      *profile.OIDCConfig,
		CredentialTemplate: template,
		ClaimEndpoint:      req.ClaimEndpoint,
		GrantType:          req.GrantType,
		ResponseType:       req.ResponseType,
		Scope:              req.Scope,
		//AuthorizationDetails: req.AuthorizationDetails,
		OpState: req.OpState,
	}

	if data.GrantType == "" {
		data.GrantType = defaultGrantType
	}

	if data.ResponseType == "" {
		data.ResponseType = defaultResponseType
	}

	if len(data.Scope) == 0 {
		data.Scope = []string{defaultScope}
	}

	tx, err := s.store.Create(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("store tx: %w", err)
	}

	return &InitiateIssuanceResponse{
		InitiateIssuanceURL: s.buildInitiateIssuanceURL(ctx, req, template, tx.ID),
		TxID:                tx.ID,
	}, nil
}

func findCredentialTemplate(
	credentialTemplates []*verifiable.Credential,
	templateID string,
) (*verifiable.Credential, error) {
	// profile should define at least one credential template
	if len(credentialTemplates) == 0 || credentialTemplates[0].ID == "" {
		return nil, errors.New("credential template not configured for profile")
	}

	// credential template ID is required if profile has more than one credential template defined
	if len(credentialTemplates) > 1 && templateID == "" {
		return nil, ErrCredentialTemplateIDRequired
	}

	for _, t := range credentialTemplates {
		if t.ID == templateID {
			return t, nil
		}
	}

	return nil, ErrCredentialTemplateNotFound
}

func (s *Service) PrepareClaimDataAuthZ(
	ctx context.Context,
	req privateapi.PrepareClaimDataAuthZRequest,
) (*privateapi.PrepareClaimDataAuthZResponse, error) {
	tx, err := s.store.FindByOpState(ctx, req.OpState)

	if err != nil {
		return nil, err
	}

	wellKnown, wellKnownErr := s.issuerWellKnownService.GetWellKnownConfiguration(
		ctx,
		tx.OIDC4VCConfig.IssuerWellKnown,
	)

	if wellKnownErr != nil {
		return nil, wellKnownErr
	}

	redirectURI, redirectErr := url.JoinPath(s.issuerVCSPublicHost, defaultCallbackPath)

	if redirectErr != nil {
		return nil, redirectErr
	}

	issuerOauthConfig := &oauth2.Config{
		ClientID:     tx.OIDC4VCConfig.ClientID,
		ClientSecret: tx.OIDC4VCConfig.ClientSecretHandle,
		RedirectURL:  redirectURI,
		Scopes:       tx.Scope,
		Endpoint: oauth2.Endpoint{
			TokenURL:  wellKnown.TokenEndpoint,
			AuthURL:   wellKnown.AuthorizationEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
	}

	tx.InternalAuthorizationResponder = &InternalAuthorizationResponder{
		RedirectURI:       req.Responder.RedirectURI,
		RespondMode:       req.Responder.RespondMode,
		AuthorizeResponse: req.Responder.AuthorizeResponse,
	}

	if updateErr := s.store.Update(ctx, tx); updateErr != nil {
		return nil, updateErr
	}

	return &privateapi.PrepareClaimDataAuthZResponse{
		RedirectURI: issuerOauthConfig.AuthCodeURL(req.OpState),
	}, nil
}

func (s *Service) HandleAuthorize(
	ctx context.Context,
	opState string,
	responder InternalAuthorizationResponder,
) (string, error) {
	resp, err := s.privateAPIClient.PrepareClaimDataAuthZ(ctx, &privateapi.PrepareClaimDataAuthZRequest{
		OpState: opState,
		Responder: privateapi.PrepareClaimResponder{
			RedirectURI:       responder.RedirectURI,
			RespondMode:       responder.RespondMode,
			AuthorizeResponse: responder.AuthorizeResponse,
		},
	})

	if err != nil {
		return "", err
	}

	return resp.RedirectURI, nil
}

func (s *Service) buildInitiateIssuanceURL(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	template *verifiable.Credential,
	txID TxID,
) string {
	var initiateIssuanceURL string

	if req.ClientInitiateIssuanceURL != "" {
		initiateIssuanceURL = req.ClientInitiateIssuanceURL
	} else if req.ClientWellKnownURL != "" {
		c, err := s.clientWellKnownService.GetWellKnownConfiguration(ctx, req.ClientWellKnownURL)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get well-known config from %q", req.ClientWellKnownURL),
				log.WithError(err))
		} else {
			initiateIssuanceURL = c.InitiateIssuanceEndpoint
		}
	}

	if initiateIssuanceURL == "" {
		initiateIssuanceURL = "openid-initiate-issuance://"
	}

	q := url.Values{}
	q.Set("issuer", s.issuerVCSPublicHost+"/"+string(txID))
	q.Set("credential_type", getCredentialType(template))
	q.Set("op_state", req.OpState)

	return initiateIssuanceURL + "?" + q.Encode()
}

func getCredentialType(template *verifiable.Credential) string {
	for _, t := range template.Types {
		if strings.EqualFold(t, "VerifiableCredential") {
			continue
		}

		return strings.ToLower(t)
	}

	return ""
}

func (s *Service) HandlePAR(ctx context.Context, opState string, ad *AuthorizationDetails) (TxID, error) {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return "", fmt.Errorf("get transaction by opstate: %w", err)
	}

	if ad.CredentialType != tx.AuthorizationDetails.CredentialType {
		return "", fmt.Errorf("authorization details credential type mismatch")
	}

	if ad.Format != tx.AuthorizationDetails.Format {
		return "", fmt.Errorf("authorization details format mismatch")
	}

	return tx.ID, nil
}
