/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination attestation_service_mocks_test.go -package attestation_test -source=attestation_service.go -mock_names httpClient=MockHTTPClient
package attestation

import (
	"context"
	"net/http"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config defines configuration for Service.
type Config struct {
	HTTPClient httpClient
}

// Service implements attestation functionality for OAuth 2.0 Attestation-Based Client Authentication.
type Service struct {
	httpClient httpClient
}

// NewService returns a new Service instance.
func NewService(config *Config) *Service {
	return &Service{
		httpClient: config.HTTPClient,
	}
}

//nolint:revive
func (s *Service) ValidateClientAttestationJWT(ctx context.Context, clientID, clientAttestationJWT string) error {
	// TODO: Validate Client Attestation JWT and check the status of Attestation VC.
	return nil
}

//nolint:revive
func (s *Service) ValidateClientAttestationPoPJWT(ctx context.Context, clientID, clientAttestationPoPJWT string) error {
	// TODO: Validate Client Attestation Proof of Possession (PoP) JWT.
	return nil
}
