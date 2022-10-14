/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4vc_service_mocks_test.go -self_package mocks -package oidc4vc_test -source=oidc4vc_service.go -mock_names transactionStorage=MockTransactionStorage,httpClient=MockHTTPClient

package oidc4vc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/vcs/internal/pkg/log"
)

const (
	defaultGrantType    = "authorization_code"
	defaultResponseType = "token"
	defaultScope        = "openid"
)

var logger = log.New("oidc4vc")

type transactionStorage interface {
	Store(ctx context.Context, data *TransactionData) (*Transaction, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds configuration options and dependencies for Service.
type Config struct {
	TransactionStorage transactionStorage
	HTTPClient         httpClient
}

// Service implements OIDC for VC issuance functionality.
type Service struct {
	store      transactionStorage
	httpClient httpClient
}

// NewService returns a new Service instance.
func NewService(config *Config) (*Service, error) {
	return &Service{
		store:      config.TransactionStorage,
		httpClient: config.HTTPClient,
	}, nil
}

// InitiateOidcInteraction prepares initiate issuance URL for starting OIDC interaction.
func (s *Service) InitiateOidcInteraction(
	ctx context.Context,
	req *InitiateIssuanceRequest,
) (*InitiateIssuanceInfo, error) {
	data := &TransactionData{
		CredentialTemplate:   req.CredentialTemplate,
		ClaimEndpoint:        req.ClaimEndpoint,
		GrantType:            req.GrantType,
		ResponseType:         req.ResponseType,
		Scope:                req.Scope,
		AuthorizationDetails: req.AuthorizationDetails,
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
		return nil, fmt.Errorf("store transaction: %w", err)
	}

	return &InitiateIssuanceInfo{
		InitiateIssuanceURL: s.buildInitiateIssuanceURL(ctx, req),
		TxID:                string(tx.ID),
	}, nil
}

func (s *Service) buildInitiateIssuanceURL(ctx context.Context, req *InitiateIssuanceRequest) string {
	var initiateIssuanceURL string

	if req.ClientInitiateIssuanceURL != "" {
		initiateIssuanceURL = req.ClientInitiateIssuanceURL
	} else if req.ClientWellKnownURL != "" {
		c, err := s.fetchWellKnownConfig(ctx, req.ClientWellKnownURL)
		if err != nil {
			logger.Error("Failed to fetch well-known config", log.WithError(err))
		} else {
			initiateIssuanceURL = c.InitiateIssuanceEndpoint
		}
	}

	if initiateIssuanceURL == "" {
		initiateIssuanceURL = "openid-initiate-issuance://"
	}

	q := url.Values{}
	q.Set("issuer", req.CredentialTemplate.Issuer.ID)
	q.Set("credential_type", req.CredentialTemplate.Types[0])
	q.Set("op_state", req.OpState) // TODO: Correlate op_state with txID.

	return initiateIssuanceURL + "?" + q.Encode()
}

type wellKnownConfig struct {
	InitiateIssuanceEndpoint string `json:"initiate_issuance_endpoint"`
}

func (s *Service) fetchWellKnownConfig(ctx context.Context, url string) (*wellKnownConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create well-known request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do well-known request: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Failed to close response body", log.WithError(closeErr))
		}
	}()

	var config wellKnownConfig

	if resp.StatusCode == http.StatusOK {
		if err = json.NewDecoder(resp.Body).Decode(&config); err != nil {
			return nil, fmt.Errorf("decode well-known config: %w", err)
		}
	}

	return &config, nil
}
