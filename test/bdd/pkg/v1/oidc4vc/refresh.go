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

	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/oidc4vp"
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

		if srv.ID == "" {
			return fmt.Errorf("refresh service endpoint is not set")
		}
	}

	return nil
}

func (s *Steps) ensureNoCredentialRefreshAvailable() error {
	for _, c := range s.issuedCredentials {
		refreshURL := c.Contents().RefreshService.ID

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
		refreshURL := c.Contents().RefreshService.ID

		resp, err := bddutil.HTTPSDo(
			http.MethodGet,
			refreshURL,
			"application/json",
			"",
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

		queryRes, _, err := s.wallet.Query(presDef, false, false)
		if err != nil {
			return fmt.Errorf("failed to query wallet: %w", err)
		}

		if len(queryRes) != 1 {
			return fmt.Errorf("expected 1 presentation, got %d", len(queryRes))
		}

		flow, err := oidc4vp.NewFlow(s.oidc4vpProvider)
		if err != nil {
			return fmt.Errorf("init flow: %w", err)
		}

		signedPres, err := flow.CreateVPToken(queryRes, &oidc4vp.RequestObject{
			ClientID: "unk",
			Nonce:    parsed.VerifiablePresentationRequest.Challenge,
			ClientMetadata: &oidc4vp.ClientMetadata{
				VPFormats: &presexch.Format{
					JwtVP: &presexch.JwtType{},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to sign presentation: %w", err)
		}

		if len(signedPres) != 1 {
			return fmt.Errorf("expected 1 signed presentation, got %d", len(signedPres))
		}

		reqBody, err := json.Marshal(oidc4ci.GetRefreshedCredentialReq{
			VerifiablePresentation: []byte(signedPres[0]),
		})
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}

		resp, err = bddutil.HTTPSDo(
			http.MethodPost,
			refreshURL,
			"application/json",
			"",
			bytes.NewBuffer(reqBody),
			s.tlsConfig,
		) //nolint: bodyclose
		if err != nil {
			return fmt.Errorf("failed to send request to refresh service (%s): %w", refreshURL, err)
		}

		if resp.Body != nil {
			body, _ = io.ReadAll(resp.Body) // nolint
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code %d and body: %s", resp.StatusCode, body)
		}

		var refreshedCredResp oidc4ci.GetRefreshedCredentialResp
		if err = json.Unmarshal(body, &refreshedCredResp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		var rawUpdatedCred []byte

		switch v := refreshedCredResp.VerifiableCredential.(type) {
		case []byte:
			rawUpdatedCred = v
		case string:
			//v, _ = strconv.Unquote(v)
			rawUpdatedCred = []byte(v)
		default:
			rawUpdatedCred, err = json.Marshal(v)
			if err != nil {
				return fmt.Errorf("failed to marshal updated credential: %w", err)
			}
		}

		parsedCred, err := verifiable.ParseCredential(rawUpdatedCred, verifiable.WithDisabledProofCheck())
		if err != nil {
			return fmt.Errorf("failed to parse updated credential: %w", err)
		}

		if parsedCred.Contents().ID == c.Contents().ID {
			return fmt.Errorf("refreshed credential has the same ID as the original one")
		}

		types := parsedCred.Contents().Types
		key := fmt.Sprintf("%s_0", types[len(types)-1])
		if err = s.wallet.Delete(key); err != nil {
			return fmt.Errorf("failed to delete old credential: %w", err)
		}

		if err = s.wallet.Add(rawUpdatedCred, key); err != nil {
			return fmt.Errorf("failed to add updated credential: %w", err)
		}

		fmt.Println("ok")
	}

	return nil
}

func (s *Steps) issuerSendRequestToInitiateCredentialRefresh() error {
	claims, err := s.fetchClaimData(s.issuedCredentialType)
	if err != nil {
		return fmt.Errorf("fetchClaimData: %w", err)
	}

	body, err := json.Marshal(issuer.SetCredentialRefreshStateRequest{
		Claims:       claims,
		CredentialId: s.issuedCredentials[0].Contents().ID,
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
