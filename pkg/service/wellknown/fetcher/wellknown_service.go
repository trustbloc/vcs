/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination wellknown_service_mocks_test.go -package fetcher_test -source=wellknown_service.go -mock_names httpClient=MockHTTPClient

package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Service is responsible for fetching Issuer's IDP OIDC Configuration.
type Service struct {
	client httpClient
}

func NewService(client httpClient) *Service {
	return &Service{
		client: client,
	}
}

// GetOIDCConfiguration returns Issuer's IDP OIDC configuration represented by oidc4ci.IssuerIDPOIDCConfiguration.
func (s *Service) GetOIDCConfiguration(
	ctx context.Context,
	issuerIDPOIDCConfigURL string,
) (*oidc4ci.IssuerIDPOIDCConfiguration, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, issuerIDPOIDCConfigURL, nil)

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

	var conf oidc4ci.IssuerIDPOIDCConfiguration

	if err = json.Unmarshal(body, &conf); err != nil {
		return nil, err
	}

	return &conf, nil
}
