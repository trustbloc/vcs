/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

//go:generate mockgen -destination well_known_service_mocks_test.go -package oidc4vc_test -source=well_known_service.go -mock_names httpClient=MockHTTPClient

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type DefaultWellKnownService[T any] struct {
	client httpClient
}

func NewDefaultIssuerWellKnownService[T any](
	client httpClient,
) *DefaultWellKnownService[T] {
	return &DefaultWellKnownService[T]{
		client: client,
	}
}

func (s *DefaultWellKnownService[T]) GetWellKnownConfiguration(
	ctx context.Context,
	url string,
) (*T, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	resp, err := s.client.Do(req)

	if err != nil {
		return nil, err
	}

	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected status code: %v", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	var result T

	if err = json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

type IssuerWellKnown struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
}

type ClientWellKnown struct {
	InitiateIssuanceEndpoint string `json:"initiate_issuance_endpoint"`
}
