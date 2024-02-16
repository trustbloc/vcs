/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"go.uber.org/zap"
)

const (
	jwtProofTypeHeader = "openid4vci-proof+jwt"
)

var logger = log.New("attestation-svc-client")

type Client struct {
	httpClient     *http.Client
	documentLoader ld.DocumentLoader
	signer         jose.Signer
	walletDID      string
	attestationURL string
}

type Config struct {
	HTTPClient     *http.Client
	DocumentLoader ld.DocumentLoader
	Signer         jose.Signer
	WalletDID      string
	AttestationURL string
}

func NewClient(config *Config) *Client {
	return &Client{
		httpClient:     config.HTTPClient,
		documentLoader: config.DocumentLoader,
		signer:         config.Signer,
		walletDID:      config.WalletDID,
		attestationURL: config.AttestationURL,
	}
}

type options struct {
	attestationRequest *AttestWalletInitRequest
}

type Opt func(*options)

func WithAttestationRequest(value *AttestWalletInitRequest) Opt {
	return func(o *options) {
		o.attestationRequest = value
	}
}

func (c *Client) GetAttestationVC(ctx context.Context, opts ...Opt) (*verifiable.Credential, error) {
	logger.Debug("get attestation vc", zap.String("walletDID", c.walletDID))

	options := &options{}

	for _, opt := range opts {
		opt(options)
	}

	initResp, err := c.attestationInit(ctx, options.attestationRequest)
	if err != nil {
		return nil, fmt.Errorf("attestation init: %w", err)
	}

	completeResp, err := c.attestationComplete(ctx, initResp.SessionID, initResp.Challenge)
	if err != nil {
		return nil, fmt.Errorf("attestation complete: %w", err)
	}

	attestationVC, err := verifiable.ParseCredential(
		[]byte(completeResp.WalletAttestationVC),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader),
	)
	if err != nil {
		return nil, fmt.Errorf("parse attestation vc: %w", err)
	}

	return attestationVC, nil
}

func (c *Client) attestationInit(ctx context.Context, req *AttestWalletInitRequest) (*AttestWalletInitResponse, error) {
	logger.Debug("attestation init started", zap.String("walletDID", c.walletDID))

	if req == nil {
		req = &AttestWalletInitRequest{
			Assertions: []string{
				"wallet_authentication",
			},
			WalletAuthentication: map[string]interface{}{
				"wallet_id": c.walletDID,
			},
			WalletMetadata: map[string]interface{}{
				"wallet_name": "wallet-cli",
			},
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var resp AttestWalletInitResponse

	if err = c.doRequest(ctx, c.attestationURL+"/init", body, &resp); err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	logger.Debug("attestation init succeeded",
		zap.String("walletDID", c.walletDID),
		zap.String("sessionID", resp.SessionID),
		zap.String("challenge", resp.Challenge),
	)

	return &resp, nil
}

func (c *Client) attestationComplete(
	ctx context.Context,
	sessionID,
	challenge string,
) (*AttestWalletCompleteResponse, error) {
	logger.Debug("attestation complete started",
		zap.String("sessionID", sessionID),
		zap.String("challenge", challenge),
	)

	claims := &JwtProofClaims{
		Issuer:   c.walletDID,
		Audience: c.attestationURL,
		IssuedAt: time.Now().Unix(),
		Exp:      time.Now().Add(time.Minute * 5).Unix(),
		Nonce:    challenge,
	}

	headers := map[string]interface{}{
		jose.HeaderType: jwtProofTypeHeader,
	}

	signedJWT, err := jwt.NewJoseSigned(claims, headers, c.signer)
	if err != nil {
		return nil, fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return nil, fmt.Errorf("serialize signed jwt: %w", err)
	}

	req := &AttestWalletCompleteRequest{
		AssuranceLevel: "low",
		Proof: Proof{
			Jwt:       jws,
			ProofType: "jwt",
		},
		SessionID: sessionID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var resp AttestWalletCompleteResponse

	if err = c.doRequest(ctx, c.attestationURL+"/complete", body, &resp); err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	logger.Debug("attestation complete succeeded",
		zap.String("sessionID", sessionID),
		zap.String("challenge", challenge),
		zap.String("attestationVC", resp.WalletAttestationVC),
	)

	return &resp, nil
}

func (c *Client) doRequest(ctx context.Context, policyURL string, body []byte, response interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, policyURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Add("content-type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d; response: %s", resp.StatusCode, string(b))
	}

	if err = json.NewDecoder(resp.Body).Decode(response); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return nil
}
