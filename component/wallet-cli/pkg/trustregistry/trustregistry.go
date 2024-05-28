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
	"io"
	"net/http"

	"github.com/samber/lo"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"
)

var (
	ErrInteractionRestricted = errors.New("interaction restricted")
	logger                   = log.New("trust-registry-client")
)

type Client struct {
	httpClient *http.Client
	host       string
}

func NewClient(httpClient *http.Client, host string) *Client {
	return &Client{
		httpClient: httpClient,
		host:       host,
	}
}

// ValidateIssuer validates that the issuer is trusted according to policy.
func (c *Client) ValidateIssuer(
	ctx context.Context,
	issuerDID string,
	issuerDomain string,
	credentialOffers []CredentialOffer,
) (bool, error) {
	endpoint := fmt.Sprintf("%s/wallet/interactions/issuance", c.host)

	logger.Debug("issuer validation begin", log.WithURL(endpoint))

	req := &WalletIssuanceRequest{
		IssuerDID:        issuerDID,
		IssuerDomain:     issuerDomain,
		CredentialOffers: credentialOffers,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("marshal wallet issuance request: %w", err)
	}

	resp, err := c.doRequest(ctx, endpoint, body)
	if err != nil {
		return false, err
	}

	if !resp.Allowed {
		if resp.DenyReasons != nil && len(*resp.DenyReasons) > 0 {
			return false, fmt.Errorf("%w: %s", ErrInteractionRestricted, lo.FromPtr(resp.DenyReasons))
		}

		return false, ErrInteractionRestricted
	}

	logger.Debug("issuer validation succeed", log.WithURL(endpoint))

	return resp.Payload != nil && lo.FromPtr(resp.Payload)["attestations_required"] != nil, nil
}

func (c *Client) ValidateVerifier(
	ctx context.Context,
	verifierDID,
	verifierDomain string,
	credentials []*verifiable.Credential,
) (bool, error) {
	endpoint := fmt.Sprintf("%s/wallet/interactions/presentation", c.host)

	logger.Debug("verifier validation begin", log.WithURL(endpoint))

	req := &WalletPresentationRequest{
		VerifierDID:       verifierDID,
		VerifierDomain:    verifierDomain,
		CredentialMatches: make([]CredentialMatches, len(credentials)),
	}

	for i, credential := range credentials {
		content := credential.Contents()

		req.CredentialMatches[i] = getCredentialMatches(content)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("marshal wallet presentation request: %w", err)
	}

	resp, err := c.doRequest(ctx, endpoint, body)
	if err != nil {
		return false, err
	}

	if !resp.Allowed {
		if resp.DenyReasons != nil && len(*resp.DenyReasons) > 0 {
			return false, fmt.Errorf("%w: %s", ErrInteractionRestricted, lo.FromPtr(resp.DenyReasons))
		}

		return false, ErrInteractionRestricted
	}

	logger.Debug("verifier validation succeed", log.WithURL(endpoint))

	return resp.Payload != nil && lo.FromPtr(resp.Payload)["attestations_required"] != nil, nil
}

func getCredentialMatches(content verifiable.CredentialContents) CredentialMatches {
	var iss, exp string
	if content.Issued != nil {
		iss = content.Issued.FormatToString()
	}

	if content.Expired != nil {
		exp = content.Expired.FormatToString()
	}

	return CredentialMatches{
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
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status code: %d, msg: %s", resp.StatusCode, string(b))
	}

	var policyEvaluationResp *PolicyEvaluationResponse

	err = json.NewDecoder(resp.Body).Decode(&policyEvaluationResp)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return policyEvaluationResp, nil
}
