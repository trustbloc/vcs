/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/refresh"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
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
	flow, err := refresh.NewFlow(s.oidc4vpProvider)
	if err != nil {
		return fmt.Errorf("init flow: %w", err)
	}

	if err = flow.Run(context.TODO()); err != nil {
		return fmt.Errorf("run flow: %w", err)
	}

	updated := flow.GetUpdatedCredentials()
	if len(updated) > 0 {
		return fmt.Errorf("unexpected refreshed credentials: %d", len(updated))
	}

	return nil
}

func (s *Steps) walletRefreshesCredential() error {
	flow, err := refresh.NewFlow(s.oidc4vpProvider)
	if err != nil {
		return fmt.Errorf("init flow: %w", err)
	}

	if err = flow.Run(context.TODO()); err != nil {
		return fmt.Errorf("run flow: %w", err)
	}

	updated := flow.GetUpdatedCredentials()
	oldToNew := map[string]*verifiable.Credential{}
	for _, upd := range updated {
		oldToNew[upd.OldCredential.Contents().ID] = upd.NewCredential
	}

	for _, issuedCred := range s.issuedCredentials {
		_, ok := oldToNew[issuedCred.Contents().ID]
		if !ok {
			return fmt.Errorf("refreshed credential not found")
		}
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
