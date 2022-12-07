/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/kms/signer"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/httputil"
)

func (s *Service) RunOIDC4VPFlow(authorizationRequest string) error {
	log.Println("Start OIDC4VP flow")
	log.Println("AuthorizationRequest:", authorizationRequest)

	log.Println("Creating wallet")
	err := s.CreateWallet()
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	log.Println("Issuing credentials")
	vcData, err := s.vcProvider.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed getting VC: %w", err)
	}

	log.Println("Saving credentials to wallet")
	for _, vcBytes := range vcData {
		err = s.SaveCredentialInWallet(vcBytes)
		if err != nil {
			return fmt.Errorf("error save VC to wallet : %w", err)
		}
	}
	log.Println(len(vcData), "credentials were saved to wallet")

	vpFlowExecutor := s.NewVPFlowExecutor(s.vcProviderConf.SkipSchemaValidation)

	log.Println("Fetching request object")
	rawRequestObject, err := vpFlowExecutor.FetchRequestObject(authorizationRequest)
	if err != nil {
		return err
	}

	log.Println("Resolving request object")
	err = vpFlowExecutor.VerifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
	if err != nil {
		return err
	}

	log.Println("Querying VC from wallet")
	err = vpFlowExecutor.QueryCredentialFromWallet()
	if err != nil {
		return err
	}

	log.Println("Creating authorized response")
	authorizedResponse, err := vpFlowExecutor.CreateAuthorizedResponse()
	if err != nil {
		return err
	}

	log.Println("Sending authorized response")
	err = vpFlowExecutor.SendAuthorizedResponse(authorizedResponse)
	if err != nil {
		return err
	}

	log.Println("Credentials shared with verifier")
	return nil
}

type VPFlowExecutor struct {
	tlsConfig            *tls.Config
	ariesServices        *ariesServices
	wallet               *wallet.Wallet
	walletToken          string
	walletDidID          string
	walletDidKeyID       string
	requestObject        *RequestObject
	requestPresentation  *verifiable.Presentation
	skipSchemaValidation bool
}

func (s *Service) NewVPFlowExecutor(skipSchemaValidation bool) *VPFlowExecutor {
	return &VPFlowExecutor{
		tlsConfig:            s.vcProviderConf.TLS,
		ariesServices:        s.ariesServices,
		wallet:               s.wallet,
		walletToken:          s.vcProviderConf.WalletParams.Token,
		walletDidID:          s.vcProviderConf.WalletParams.DidID,
		walletDidKeyID:       s.vcProviderConf.WalletParams.DidKeyID,
		skipSchemaValidation: skipSchemaValidation,
	}
}

func (e *VPFlowExecutor) InitiateInteraction(url, authToken string) (*InitiateOIDC4VPResponse, error) {
	resp, err := httputil.HTTPSDo(http.MethodPost, url, "application/json", authToken, //nolint: bodyclose
		nil, e.tlsConfig)
	if err != nil {
		return nil, err
	}

	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	result := &InitiateOIDC4VPResponse{}

	return result, json.Unmarshal(respBytes, result)
}

func (e *VPFlowExecutor) FetchRequestObject(authorizationRequest string) (string, error) {
	endpointURL := strings.TrimPrefix(authorizationRequest, "openid-vc://?request_uri=")

	resp, err := httputil.HTTPSDo(http.MethodGet, endpointURL, "", "", nil, e.tlsConfig)
	if err != nil {
		return "", err
	}
	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	return string(respBytes), nil
}

func (e *VPFlowExecutor) RequestPresentation() *verifiable.Presentation {
	return e.requestPresentation
}

func (e *VPFlowExecutor) RetrieveInteractionsClaim(url, authToken string) error {
	resp, err := httputil.HTTPSDo(http.MethodGet, url, "application/json", authToken, //nolint: bodyclose
		nil, e.tlsConfig)
	if err != nil {
		return err
	}
	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	return nil
}

func (e *VPFlowExecutor) VerifyAuthorizationRequestAndDecodeClaims(rawRequestObject string) error {
	jwtVerifier := jwt.NewVerifier(jwt.KeyResolverFunc(
		verifiable.NewVDRKeyResolver(e.ariesServices.vdrRegistry).PublicKeyFetcher()))

	requestObject := &RequestObject{}

	err := verifyTokenSignature(rawRequestObject, requestObject, jwtVerifier)
	if err != nil {
		return err
	}

	e.requestObject = requestObject
	return nil
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

func (e *VPFlowExecutor) QueryCredentialFromWallet() error {
	if e.skipSchemaValidation && len(e.requestObject.Claims.VPToken.PresentationDefinition.InputDescriptors) > 0 { // bypass
		oldScheme := e.requestObject.Claims.VPToken.PresentationDefinition.InputDescriptors[0].Schema
		e.requestObject.Claims.VPToken.PresentationDefinition.InputDescriptors[0].Schema = nil
		defer func() {
			e.requestObject.Claims.VPToken.PresentationDefinition.InputDescriptors[0].Schema = oldScheme
		}()
	}

	pdBytes, err := json.Marshal(e.requestObject.Claims.VPToken.PresentationDefinition)

	if err != nil {
		return fmt.Errorf("presentation definition marshal: %w", err)
	}

	vps, err := e.wallet.Query(e.walletToken, &wallet.QueryParams{
		Type:  "PresentationExchange",
		Query: []json.RawMessage{pdBytes},
	})

	if err != nil {
		return fmt.Errorf("query vc using presentation definition: %w", err)
	}

	e.requestPresentation = vps[0]

	return nil
}

func (e *VPFlowExecutor) CreateAuthorizedResponse() (string, error) {
	presentationSubmission :=
		e.requestPresentation.CustomFields["presentation_submission"].(*presexch.PresentationSubmission)

	idToken := &IDTokenClaims{
		VPToken: IDTokenVPToken{
			PresentationSubmission: presentationSubmission,
		},
		Nonce: e.requestObject.Nonce,
		Exp:   time.Now().Unix() + 600,
		Iss:   "https://self-issued.me/v2/openid-vc",
	}

	e.requestPresentation.CustomFields["presentation_submission"] = nil

	vpToken := VPTokenClaims{
		VP:    e.requestPresentation,
		Nonce: e.requestObject.Nonce,
		Exp:   time.Now().UTC().Unix() + 600,
		Iss:   e.walletDidID,
	}

	idTokenJWS, err := signToken(idToken, e.walletDidKeyID, e.ariesServices.crypto, e.ariesServices.kms)
	if err != nil {
		return "", fmt.Errorf("sign id_token: %w", err)
	}

	vpTokenJWS, err := signToken(vpToken, e.walletDidKeyID, e.ariesServices.crypto, e.ariesServices.kms)
	if err != nil {
		return "", fmt.Errorf("sign vp_token: %w", err)
	}

	return fmt.Sprintf("id_token=%s&vp_token=%s&state=%s", idTokenJWS, vpTokenJWS, e.requestObject.State), nil
}

func signToken(claims interface{}, didKeyID string, crpt crypto.Crypto,
	km kms.KeyManager) (string, error) {

	kmsSigner, err := signer.NewKMSSigner(km, crpt, didKeyID, "ES384", nil)
	if err != nil {
		return "", fmt.Errorf("create kms signer: %w", err)
	}

	token, err := jwt.NewSigned(claims, nil, NewJWSSigner(didKeyID, "ES384", kmsSigner))
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: sign token failed: %w", err)
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: serialize token failed: %w", err)
	}

	return tokenBytes, nil
}

func (e *VPFlowExecutor) SendAuthorizedResponse(responseBody string) error {
	req, err := http.NewRequest(http.MethodPost, e.requestObject.RedirectURI, bytes.NewBuffer([]byte(responseBody)))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: e.tlsConfig}}

	resp, err := c.Do(req)

	if err != nil {
		return err
	}

	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	return nil
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
