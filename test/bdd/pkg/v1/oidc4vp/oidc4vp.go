/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/vcs/pkg/doc/vc/jws"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/kms/signer"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

const (
	// retry options to pull topics from webhook
	// pullTopicsWaitInMilliSec is time in milliseconds to wait before retry.
	pullTopicsWaitInMilliSec = 200
	// pullTopicsAttemptsBeforeFail total number of retries where
	// total time shouldn't exceed 5 seconds.
	pullTopicsAttemptsBeforeFail = 5000 / pullTopicsWaitInMilliSec
)

type initiateOIDC4VPResponse struct {
	AuthorizationRequest string `json:"authorizationRequest"`
	TxId                 string `json:"txID"`
}

type RequestObject struct {
	JTI          string                    `json:"jti"`
	IAT          int64                     `json:"iat"`
	ResponseType string                    `json:"response_type"`
	ResponseMode string                    `json:"response_mode"`
	Scope        string                    `json:"scope"`
	Nonce        string                    `json:"nonce"`
	ClientID     string                    `json:"client_id"`
	RedirectURI  string                    `json:"redirect_uri"`
	State        string                    `json:"state"`
	Exp          int64                     `json:"exp"`
	Registration RequestObjectRegistration `json:"registration"`
	Claims       RequestObjectClaims       `json:"claims"`
}

type RequestObjectRegistration struct {
	ClientName                  string           `json:"client_name"`
	SubjectSyntaxTypesSupported []string         `json:"subject_syntax_types_supported"`
	VPFormats                   *presexch.Format `json:"vp_formats"`
	ClientPurpose               string           `json:"client_purpose"`
}

type RequestObjectClaims struct {
	VPToken VPToken `json:"vp_token"`
}
type VPToken struct {
	PresentationDefinition *presexch.PresentationDefinition `json:"presentation_definition"`
}

type IDTokenVPToken struct {
	PresentationSubmission *presexch.PresentationSubmission `json:"presentation_submission"`
}

type IDTokenClaims struct {
	VPToken IDTokenVPToken `json:"_vp_token"`
	Nonce   string         `json:"nonce"`
	Exp     int64          `json:"exp"`
	Iss     string         `json:"iss"`
}

type VPTokenClaims struct {
	VP    *verifiable.Presentation `json:"vp"`
	Nonce string                   `json:"nonce"`
	Exp   int64                    `json:"exp"`
	Iss   string                   `json:"iss"`
}

func (e *Steps) initiateInteraction(profileName, organizationName string) error {
	e.vpFlowExecutor = &VPFlowExecutor{
		tlsConfig:      e.tlsConfig,
		ariesServices:  e.ariesServices,
		wallet:         e.wallet,
		walletToken:    e.walletToken,
		walletDidID:    e.walletDidID,
		walletDidKeyID: e.walletDidKeyID,
		URLs: &VPFlowExecutorURLs{
			InitiateOidcInteractionURLFormat:   initiateOidcInteractionURLFormat,
			RetrieveInteractionsClaimURLFormat: retrieveInteractionsClaimURLFormat,
		},
	}

	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]
	return e.vpFlowExecutor.initiateInteraction(profileName, token)
}

func (e *Steps) verifyAuthorizationRequestAndDecodeClaims() error {
	rawRequestObject, err := e.vpFlowExecutor.fetchRequestObject()
	if err != nil {
		return err
	}

	_, err = e.waitForEvent("oidc_interaction_qr_scanned")
	if err != nil {
		return err
	}

	return e.vpFlowExecutor.verifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
}

func (e *Steps) queryCredentialFromWallet() error {
	return e.vpFlowExecutor.queryCredentialFromWallet()
}

func (e *Steps) sendAuthorizedResponse() error {
	body, err := e.vpFlowExecutor.createAuthorizedResponse()
	if err != nil {
		return err
	}

	return e.vpFlowExecutor.sendAuthorizedResponse(body)
}

func (e *Steps) retrieveInteractionsClaim(organizationName string) error {
	txID, err := e.waitForEvent("oidc_interaction_succeeded")
	if err != nil {
		return err
	}

	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]

	e.vpFlowExecutor.claimsTransactionID = txID

	return e.vpFlowExecutor.retrieveInteractionsClaim(txID, token, http.StatusOK)
}

func (e *Steps) retrieveExpiredInteractionsClaim(organizationName string) error {
	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]

	txID := e.vpFlowExecutor.claimsTransactionID

	return e.vpFlowExecutor.retrieveInteractionsClaim(txID, token, http.StatusInternalServerError)
}

func (e *Steps) waitForEvent(eventType string) (string, error) {
	incoming := &spi.Event{}

	for i := 0; i < pullTopicsAttemptsBeforeFail; {

		resp, err := bddutil.HTTPSDo(http.MethodGet, oidc4vpWebhookURL, "application/json", "", //nolint: bodyclose
			nil, e.tlsConfig)
		if err != nil {
			return "", err
		}
		defer bddutil.CloseResponseBody(resp.Body)

		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		if resp.StatusCode != http.StatusOK {
			return "", bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
		}

		err = json.Unmarshal(respBytes, incoming)
		if err != nil {
			return "", err
		}

		if incoming.Type == spi.EventType(eventType) {
			return incoming.TransactionID, nil
		}

		i++
		time.Sleep(pullTopicsWaitInMilliSec * time.Millisecond)
	}
	return "", errors.New("webhook waiting timeout exited")
}

func verifyTokenSignature(rawJwt string, claims interface{}, verifier jose.SignatureVerifier) error {
	jsonWebToken, err := jwt.Parse(rawJwt, jwt.WithSignatureVerifier(verifier))
	if err != nil {
		return fmt.Errorf("parse JWT: %w", err)
	}

	err = jsonWebToken.DecodeClaims(claims)
	if err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}

	return nil
}

func signToken(claims interface{}, didKeyID string, crpt crypto.Crypto,
	km kms.KeyManager) (string, error) {

	signr, err := signer.NewKMSSigner(km, crpt, strings.Split(didKeyID, "#")[1], "ES384", nil)

	token, err := jwt.NewSigned(claims, nil, jws.NewSigner(didKeyID, "ES384", signr))
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: sign token failed: %w", err)
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: serialize token failed: %w", err)
	}

	return tokenBytes, nil
}
