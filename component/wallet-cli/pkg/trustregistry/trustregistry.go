/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package trustregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"
)

var (
	ErrInteractionRestricted = errors.New("interaction restricted")
	logger                   = log.New("trust-registry-client")
)

type Client struct {
	httpClient       *http.Client
	trustRegistryURL string
}

func NewClient(httpClient *http.Client, policyURL string) *Client {
	return &Client{
		httpClient:       httpClient,
		trustRegistryURL: policyURL,
	}
}

func (c *Client) ValidateIssuer(
	issuerDID,
	issuerDomain,
	credentialType,
	credentialFormat string,
	clientAttestationRequested bool,
) error {
	logger.Debug("issuer validation begin")

	req := &WalletIssuanceRequest{
		ClientAttestationRequested: clientAttestationRequested,
		CredentialFormat:           credentialFormat,
		CredentialType:             credentialType,
		IssuerDID:                  issuerDID,
		IssuerDomain:               issuerDomain,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal wallet issuance request: %w", err)
	}

	resp, err := c.doRequest(context.Background(), c.trustRegistryURL, body)
	if err != nil {
		return err
	}

	if !resp.Allowed {
		return ErrInteractionRestricted
	}

	logger.Debug("issuer validation succeed")

	return nil
}

func (c *Client) ValidateVerifier(
	verifierDID,
	verifierDomain string,
	credentials []*verifiable.Credential,
) error {
	logger.Debug("verifier validation begin")

	req := &WalletPresentationRequest{
		VerifierDID:        verifierDID,
		VerifierDomain:     verifierDomain,
		CredentialMetadata: make([]CredentialMetadata, len(credentials)),
	}

	for i, credential := range credentials {
		content := credential.Contents()

		req.CredentialMetadata[i] = getCredentialMetadata(content)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal wallet presentation request: %w", err)
	}

	resp, err := c.doRequest(context.Background(), c.trustRegistryURL, body)
	if err != nil {
		return err
	}

	if !resp.Allowed {
		return ErrInteractionRestricted
	}

	logger.Debug("verifier validation succeed")

	return nil
}

func getCredentialMetadata(content verifiable.CredentialContents) CredentialMetadata {
	var iss, exp string
	if content.Issued != nil {
		iss = content.Issued.FormatToString()
	}

	if content.Expired != nil {
		exp = content.Expired.FormatToString()
	}

	return CredentialMetadata{
		CredentialID:    content.ID,
		CredentialTypes: content.Types,
		ExpirationDate:  exp,
		IssuanceDate:    iss,
		IssuerID:        content.Issuer.ID,
	}
}

func (c *Client) doRequest(ctx context.Context, policyURL string, body []byte) (*PolicyEvaluationResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, policyURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Add("content-type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var policyEvaluationResp *PolicyEvaluationResponse

	err = json.NewDecoder(resp.Body).Decode(&policyEvaluationResp)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return policyEvaluationResp, nil
}
