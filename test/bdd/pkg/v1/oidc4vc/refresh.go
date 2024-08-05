/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

func (s *Steps) ensureCredentialServiceSet() error {
	if len(s.issuedCredentials) == 0 {
		return fmt.Errorf("no credentials issued")
	}

	for _, cred := range s.issuedCredentials {
		srv := cred.Contents().RefreshService
		if srv == nil {
			return fmt.Errorf("refresh service is not set")
		}

		if srv.Type != "VerifiableCredentialRefreshService2021" {
			return fmt.Errorf("unexpected refresh service type: %s", srv.Type)
		}

		if srv.Url == "" {
			return fmt.Errorf("refresh service endpoint is not set")
		}
	}

	return nil
}

func (s *Steps) ensureNoCredentialRefreshAvailable() error {
	for _, c := range s.issuedCredentials {
		refreshURL := c.Contents().RefreshService.Url

		resp, err := bddutil.HTTPSDo(
			http.MethodGet,
			refreshURL,
			"application/json",
			s.getToken(),
			nil,
			s.tlsConfig,
		) //nolint: bodyclose
		if err != nil {
			return fmt.Errorf("failed to send request to refresh service (%s): %w", refreshURL, err)
		}

		var body []byte
		if resp.Body != nil {
			body, _ = io.ReadAll(resp.Body) // nolint
		}

		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("unexpected status code %d and body: %s", resp.StatusCode, body)
		}
	}

	return nil
}

func (s *Steps) walletRefreshesCredential() error {
	for _, c := range s.issuedCredentials {
		refreshURL := c.Contents().RefreshService.Url

		resp, err := bddutil.HTTPSDo(
			http.MethodGet,
			refreshURL,
			"application/json",
			s.getToken(),
			nil,
			s.tlsConfig,
		) //nolint: bodyclose
		if err != nil {
			return fmt.Errorf("failed to send request to refresh service (%s): %w", refreshURL, err)
		}

		var body []byte
		if resp.Body != nil {
			body, _ = io.ReadAll(resp.Body) // nolint
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code %d and body: %s", resp.StatusCode, body)
		}

		var parsed oidc4ci.CredentialRefreshAvailableResponse
		if err = json.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		presDef, err := json.Marshal(parsed.VerifiablePresentationRequest.Query)
		if err != nil {
			return fmt.Errorf("failed to marshal presentation definition: %w", err)
		}

		queryRes, presSub, err := s.wallet.Query(presDef, false, false)
		if err != nil {
			return fmt.Errorf("failed to query wallet: %w", err)
		}

		fmt.Print(queryRes, presSub)
	}

	return nil
}

func (s *Steps) issuerSendRequestToInitiateCredentialRefresh() error {
	claims, err := s.fetchClaimData(s.issuedCredentialType)
	if err != nil {
		return fmt.Errorf("fetchClaimData: %w", err)
	}

	body, err := json.Marshal(issuer.SetCredentialRefreshStateRequest{
		Claims:                claims,
		CredentialDescription: lo.ToPtr("some-description"),
		CredentialId:          s.issuedCredentials[0].Contents().ID,
		CredentialName:        lo.ToPtr("some-name"),
	})
	if err != nil {
		return fmt.Errorf("marshal request payload: %w", err)
	}

	resp, err := bddutil.HTTPSDo(
		http.MethodPost,
		fmt.Sprintf("%s/issuer/profiles/%s/%s/interactions/refresh",
			vcsAPIGateway,
			s.issuerProfile.ID,
			s.issuerProfile.Version,
		),
		"application/json",
		s.getToken(),
		bytes.NewReader(body),
		s.tlsConfig,
	) //nolint: bodyclose

	if err != nil {
		return err
	}
	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	var result issuer.SetCredentialRefreshStateResult
	if err = json.Unmarshal(respBytes, &result); err != nil {
		return fmt.Errorf("decode response payload: %w", err)
	}

	if result.TransactionId == "" {
		return fmt.Errorf("missing transaction ID in response")
	}

	return nil
}
