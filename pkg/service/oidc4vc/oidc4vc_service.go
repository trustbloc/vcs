/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4vc_service_mocks_test.go -self_package mocks -package oidc4vc_test -source=oidc4vc_service.go -mock_names transactionStore=MockTransactionStore,httpClient=MockHTTPClient

package oidc4vc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/vcs/internal/pkg/log"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

const (
	defaultGrantType    = "authorization_code"
	defaultResponseType = "token"
	defaultScope        = "openid"
)

var logger = log.New("oidc4vc")

type transactionStore interface {
	Store(ctx context.Context, data *TransactionData) (*Transaction, error)
	GetByOpState(ctx context.Context, opState string) (*Transaction, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds configuration options and dependencies for Service.
type Config struct {
	TransactionStore transactionStore
	HTTPClient       httpClient
}

// Service implements OIDC for VC issuance functionality.
type Service struct {
	store      transactionStore
	httpClient httpClient
}

// NewService returns a new Service instance.
func NewService(config *Config) (*Service, error) {
	return &Service{
		store:      config.TransactionStore,
		httpClient: config.HTTPClient,
	}, nil
}

// InitiateInteraction creates credential issuance transaction and builds initiate issuance URL.
func (s *Service) InitiateInteraction(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	profile *profileapi.Issuer,
) (*InitiateIssuanceResponse, error) {
	data := &TransactionData{
		CredentialTemplate:   req.CredentialTemplate,
		ClaimEndpoint:        req.ClaimEndpoint,
		GrantType:            req.GrantType,
		ResponseType:         req.ResponseType,
		Scope:                req.Scope,
		AuthorizationDetails: req.AuthorizationDetails,
		OpState:              req.OpState,
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

	tx, err := s.store.Store(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("store tx: %w", err)
	}

	return &InitiateIssuanceResponse{
		InitiateIssuanceURL: s.buildInitiateIssuanceURL(ctx, req, profile),
		TxID:                tx.ID,
	}, nil
}

func (s *Service) buildInitiateIssuanceURL(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	profile *profileapi.Issuer,
) string {
	var initiateIssuanceURL string

	if req.ClientInitiateIssuanceURL != "" {
		initiateIssuanceURL = req.ClientInitiateIssuanceURL
	} else if req.ClientWellKnownURL != "" {
		c, err := s.getClientWellKnownConfig(ctx, req.ClientWellKnownURL)
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
	q.Set("issuer", profile.ID)
	q.Set("credential_type", req.AuthorizationDetails.CredentialType)
	q.Set("op_state", req.OpState)

	return initiateIssuanceURL + "?" + q.Encode()
}

func (s *Service) getClientWellKnownConfig(ctx context.Context, wellKnownURL string) (*ClientWellKnownConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create well-known config req: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do well-known config req: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Failed to close response body", log.WithError(closeErr))
		}
	}()

	var config ClientWellKnownConfig

	if resp.StatusCode == http.StatusOK {
		if err = json.NewDecoder(resp.Body).Decode(&config); err != nil {
			return nil, fmt.Errorf("unmarshal well-known config: %w", err)
		}
	}

	return &config, nil
}

func (s *Service) HandlePAR(ctx context.Context, opState string, ad *AuthorizationDetails) (TxID, error) {
	tx, err := s.store.GetByOpState(ctx, opState)
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
