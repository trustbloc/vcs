/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4vc_service_mocks_test.go -self_package mocks -package oidc4vc_test -source=oidc4vc_service.go -mock_names transactionStore=MockTransactionStore,wellKnownService=MockWellKnownService,oAuth2Client=MockOAuth2Client,httpClient=MockHTTPClient

package oidc4vc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/trustbloc/logutil-go/pkg/log"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/oauth2client"
)

const (
	defaultGrantType    = "authorization_code"
	defaultResponseType = "token"
	defaultScope        = "openid"
)

var logger = log.New("oidc4vc")

type transactionStore interface {
	Create(
		ctx context.Context,
		data *TransactionData,
		params ...func(insertOptions *InsertOptions),
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

type oAuth2Client interface {
	Exchange(
		ctx context.Context,
		cfg oauth2.Config,
		code string,
		client *http.Client,
		opts ...oauth2client.AuthCodeOption,
	) (*oauth2.Token, error)
}

type wellKnownService interface {
	GetOIDCConfiguration(ctx context.Context, url string) (*OIDCConfiguration, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds configuration options and dependencies for Service.
type Config struct {
	TransactionStore    transactionStore
	WellKnownService    wellKnownService
	IssuerVCSPublicHost string
	OAuth2Client        oAuth2Client
	HTTPClient          httpClient
}

// Service implements VCS credential interaction API for OIDC4VC issuance.
type Service struct {
	store               transactionStore
	wellKnownService    wellKnownService
	issuerVCSPublicHost string
	oAuth2Client        oAuth2Client
	httpClient          httpClient
}

// NewService returns a new Service instance.
func NewService(config *Config) (*Service, error) {
	return &Service{
		store:               config.TransactionStore,
		wellKnownService:    config.WellKnownService,
		issuerVCSPublicHost: config.IssuerVCSPublicHost,
		oAuth2Client:        config.OAuth2Client,
		httpClient:          config.HTTPClient,
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
			return nil, err
		}
	}

	return &PrepareClaimDataAuthorizationResponse{
		AuthorizationParameters: &OAuthParameters{
			ClientID:     tx.ClientID,
			ClientSecret: tx.ClientSecret,
			ResponseType: req.ResponseType,
			Scope:        req.Scope,
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

	if ad.Format != tx.CredentialFormat {
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

	if tx.PreAuthCode != preAuthorizedCode || (tx.UserPinRequired && len(pin) == 0) {
		// todo in future add proper pin validation
		return nil, errors.New("invalid auth credentials")
	}

	return tx, nil
}

func (s *Service) PrepareCredential(
	ctx context.Context,
	req *CredentialRequest,
) (*CredentialResponse, error) {
	tx, err := s.store.FindByOpState(ctx, req.OpState)
	if err != nil {
		return nil, fmt.Errorf("find tx by op state: %w", err)
	}

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

	// TODO: Prepare and sign credential

	return &CredentialResponse{
		TxID:       tx.ID,
		Credential: "",
		Retry:      false,
	}, nil
}
