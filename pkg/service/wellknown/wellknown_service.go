/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination wellknown_service_mocks_test.go -package wellknown_test -source=wellknown_service.go -mock_names httpClient=MockHTTPClient

package wellknown

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

type Service struct {
	client httpClient
}

func NewService(client httpClient) *Service {
	return &Service{
		client: client,
	}
}

func (s *Service) GetOIDCConfiguration(ctx context.Context, url string) (*oidc4ci.OIDCConfiguration, error) {
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

	var conf oidc4ci.OIDCConfiguration

	if err = json.Unmarshal(body, &conf); err != nil {
		return nil, err
	}

	return &conf, nil
}
