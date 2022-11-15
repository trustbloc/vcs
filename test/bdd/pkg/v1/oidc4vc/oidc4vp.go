/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/vcs/pkg/doc/vc"
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

	credentialServiceURL               = "https://localhost:4455"
	oidc4vpWebhookURL                  = "http://localhost:8180/checktopics"
	verifierProfileURL                 = credentialServiceURL + "/verifier/profiles"
	verifierProfileURLFormat           = verifierProfileURL + "/%s"
	initiateOidcInteractionURLFormat   = verifierProfileURLFormat + "/interactions/initiate-oidc"
	retrieveInteractionsClaimURLFormat = credentialServiceURL + "/verifier/interactions/%s/claim"
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

type Event struct {
	// ID identifies the event(required).
	ID string `json:"id"`

	// Source is URI for producer(required).
	Source string `json:"source"`

	// Type defines event type(required).
	Type string `json:"type"`

	// DataContentType is data content type(required).
	DataContentType string `json:"datacontenttype"`

	// Data defines message(required).
	Data *EventPayload `json:"data"`
}

type EventPayload struct {
	TxID    string `json:"txID"`
	WebHook string `json:"webHook,omitempty"`
}

func (s *Steps) initiateInteraction(profileName, organizationName string) error {
	s.vpFlowExecutor = &VPFlowExecutor{
		tlsConfig:      s.tlsConfig,
		ariesServices:  s.ariesServices,
		wallet:         s.wallet,
		walletToken:    s.walletToken,
		walletDidID:    s.walletDidID,
		walletDidKeyID: s.walletDidKeyID,
		URLs: &VPFlowExecutorURLs{
			InitiateOidcInteractionURLFormat:   initiateOidcInteractionURLFormat,
			RetrieveInteractionsClaimURLFormat: retrieveInteractionsClaimURLFormat,
		},
	}

	token := s.bddContext.Args[getOrgAuthTokenKey(organizationName)]
	return s.vpFlowExecutor.initiateInteraction(profileName, token)
}

func (s *Steps) verifyAuthorizationRequest() error {
	if len(s.vpFlowExecutor.authorizationRequest) == 0 {
		return fmt.Errorf("authorizationRequest is empty")
	}

	if len(s.vpFlowExecutor.transactionID) == 0 {
		return fmt.Errorf("transactionID is empty")
	}

	return nil
}

func (s *Steps) fetchRequestRequestObjectAndDecodeClaims() error {
	rawRequestObject, err := s.vpFlowExecutor.fetchRequestObject()
	if err != nil {
		return err
	}

	_, err = s.waitForEvent("oidc_interaction_qr_scanned")
	if err != nil {
		return err
	}

	return s.vpFlowExecutor.verifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
}

func (s *Steps) queryCredentialFromWallet() error {
	return s.vpFlowExecutor.queryCredentialFromWallet()
}

func (s *Steps) checkRequestPresentation() error {
	if s.vpFlowExecutor.requestPresentation == nil {
		return fmt.Errorf("requestPresentation is empty")
	}

	return nil
}

func (s *Steps) sendAuthorizedResponse() error {
	body, err := s.vpFlowExecutor.createAuthorizedResponse()
	if err != nil {
		return err
	}

	return s.vpFlowExecutor.sendAuthorizedResponse(body)
}

func (s *Steps) retrieveInteractionsClaim(organizationName string) error {
	txID, err := s.waitForEvent("oidc_interaction_succeeded")
	if err != nil {
		return err
	}

	token := s.bddContext.Args[getOrgAuthTokenKey(organizationName)]

	return s.vpFlowExecutor.retrieveInteractionsClaim(txID, token)
}

func (s *Steps) waitForEvent(eventType string) (string, error) {
	incoming := &Event{}

	for i := 0; i < pullTopicsAttemptsBeforeFail; {

		resp, err := bddutil.HTTPSDo(http.MethodGet, oidc4vpWebhookURL, "application/json", "", //nolint: bodyclose
			nil, s.tlsConfig)
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

		if incoming.Type == eventType {
			return incoming.Data.TxID, nil
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

	signr, err := signer.NewKMSSigner(km, crpt, didKeyID, "ES384", nil)

	token, err := jwt.NewSigned(claims, nil, NewJWSSigner(didKeyID, "ES384", signr))
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: sign token failed: %w", err)
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: serialize token failed: %w", err)
	}

	return tokenBytes, nil
}

type JWSSigner struct {
	keyID            string
	signingAlgorithm string
	signer           vc.SignerAlgorithm
}

func NewJWSSigner(keyID string, signingAlgorithm string, signer vc.SignerAlgorithm) *JWSSigner {
	return &JWSSigner{
		keyID:            keyID,
		signingAlgorithm: signingAlgorithm,
		signer:           signer,
	}
}

// Sign signs.
func (s *JWSSigner) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

// Headers provides JWS headers. "alg" header must be provided (see https://tools.ietf.org/html/rfc7515#section-4.1)
func (s *JWSSigner) Headers() jose.Headers {
	return jose.Headers{
		jose.HeaderKeyID:     s.keyID,
		jose.HeaderAlgorithm: s.signingAlgorithm,
	}
}
