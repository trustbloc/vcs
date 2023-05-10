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
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	didkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/httputil"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms/signer"
)

func (s *Service) RunOIDC4VPFlow(authorizationRequest string) error {
	log.Println("Start OIDC4VP flow")
	log.Println("AuthorizationRequest:", authorizationRequest)

	err := s.CreateWallet()
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	if s.vcProviderConf.OIDC4VPShouldFetchCredentials {
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
	} else {
		log.Println("Using existing credentials")
	}

	s.vpFlowExecutor = s.NewVPFlowExecutor(s.vcProviderConf.SkipSchemaValidation)

	log.Println("Fetching request object")
	startTime := time.Now()
	rawRequestObject, dur, err := s.vpFlowExecutor.FetchRequestObject(authorizationRequest)
	s.perfInfo.FetchRequestObject = dur
	s.perfInfo.VcsVPFlowDuration += dur
	if err != nil {
		return err
	}

	log.Println("Resolving request object")
	startTime = time.Now()
	err = s.vpFlowExecutor.VerifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
	if err != nil {
		return err
	}

	if s.vcProviderConf.LinkedDomainVerificationEnabled {
		if err := s.runLinkedDomainVerification(s.vpFlowExecutor.requestObject.ClientID); err != nil {
			return fmt.Errorf("linked domain verification failed: %w", err)
		}
	}

	s.perfInfo.VerifyAuthorizationRequest = time.Since(startTime)

	log.Println("Querying VC from wallet")
	startTime = time.Now()
	err = s.vpFlowExecutor.QueryCredentialFromWallet()
	if err != nil {
		return err
	}
	s.perfInfo.QueryCredentialFromWallet = time.Since(startTime)
	s.wallet.Close()

	log.Println("Creating authorized response")
	startTime = time.Now()
	authorizedResponse, err := s.vpFlowExecutor.CreateAuthorizedResponse()
	if err != nil {
		return err
	}
	s.perfInfo.CreateAuthorizedResponse = time.Since(startTime)

	log.Println("Sending authorized response")
	startTime = time.Now()
	dur, err = s.vpFlowExecutor.SendAuthorizedResponse(authorizedResponse)
	s.perfInfo.SendAuthorizedResponse = dur
	s.perfInfo.VcsVPFlowDuration += dur
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
	walletSignType       vcs.SignatureType
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
		walletSignType:       s.vcProviderConf.WalletParams.SignType,
		skipSchemaValidation: skipSchemaValidation,
	}
}

func (s *Service) GetVPFlowExecutor() *VPFlowExecutor {
	return s.vpFlowExecutor
}

func (e *VPFlowExecutor) InitiateInteraction(url, authToken string, body io.Reader) (*InitiateOIDC4VPResponse, error) {
	resp, err := httputil.HTTPSDo(http.MethodPost, url, "application/json", authToken, //nolint: bodyclose
		body, e.tlsConfig)
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

func (e *VPFlowExecutor) FetchRequestObject(authorizationRequest string) (string, time.Duration, error) {
	endpointURL := strings.TrimPrefix(authorizationRequest, "openid-vc://?request_uri=")

	st := time.Now()
	resp, err := httputil.HTTPSDo(http.MethodGet, endpointURL, "", "", nil, e.tlsConfig)
	dur := time.Since(st)
	if err != nil {
		return "", dur, err
	}
	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", dur, err
	}

	if resp.StatusCode != http.StatusOK {
		return "", dur, fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	return string(respBytes), dur, nil
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

	rawData, err := verifyTokenSignature(rawRequestObject, jwtVerifier)
	if err != nil {
		return err
	}

	err = json.Unmarshal(rawData, requestObject)
	if err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}

	e.requestObject = requestObject

	return nil
}

func verifyTokenSignature(rawJwt string, verifier jose.SignatureVerifier) ([]byte, error) {
	_, rawData, err := jwt.Parse(
		rawJwt,
		jwt.WithSignatureVerifier(verifier),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	return rawData, nil
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

	vps[0].Context = []string{"https://www.w3.org/2018/credentials/v1"}
	vps[0].Type = []string{"VerifiablePresentation"}
	vps[0].CustomFields["presentation_submission"].(*presexch.PresentationSubmission).DescriptorMap[0].Format = "jwt_vp"
	vps[0].CustomFields["presentation_submission"].(*presexch.PresentationSubmission).DescriptorMap[0].Path = "$"
	vps[0].CustomFields["presentation_submission"].(*presexch.PresentationSubmission).DescriptorMap[0].PathNested =
		&presexch.InputDescriptorMapping{
			ID:     vps[0].CustomFields["presentation_submission"].(*presexch.PresentationSubmission).DescriptorMap[0].ID,
			Format: "jwt_vc",
			Path:   "$.verifiableCredential[0]",
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
		Aud:   e.requestObject.ClientID,
		Sub:   e.walletDidID,
		Nbf:   time.Now().Unix(),
		Iat:   time.Now().Unix(),
		Jti:   uuid.NewString(),
	}

	delete(e.requestPresentation.CustomFields, "presentation_submission")

	vpToken := VPTokenClaims{
		VP:    e.requestPresentation,
		Nonce: e.requestObject.Nonce,
		Exp:   time.Now().Unix() + 600,
		Iss:   e.walletDidID,
		Aud:   e.requestObject.ClientID,
		Nbf:   time.Now().Unix(),
		Iat:   time.Now().Unix(),
		Jti:   uuid.NewString(),
	}

	idTokenJWS, err := signToken(idToken, e.walletDidKeyID, e.ariesServices.crypto, e.ariesServices.kms, e.walletSignType)
	if err != nil {
		return "", fmt.Errorf("sign id_token: %w", err)
	}

	bytes, err := json.Marshal(vpToken)
	if err != nil {
		return "", err
	}

	bytesNew := strings.ReplaceAll(string(bytes), "\"VerifiablePresentation\"", `["VerifiablePresentation"]`)

	vpTokenJWS, err := signToken(bytesNew, e.walletDidKeyID, e.ariesServices.crypto, e.ariesServices.kms, e.walletSignType)
	if err != nil {
		return "", fmt.Errorf("sign vp_token: %w", err)
	}

	data := url.Values{}
	data.Set("id_token", idTokenJWS)
	data.Set("vp_token", vpTokenJWS)
	data.Set("state", e.requestObject.State)

	return data.Encode(), nil
}

func signToken(claims interface{}, didKeyID string, crpt crypto.Crypto,
	km kms.KeyManager, signType vcs.SignatureType) (string, error) {

	kmsSigner, err := signer.NewKMSSigner(km, crpt, strings.Split(didKeyID, "#")[1], signType, nil)
	if err != nil {
		return "", fmt.Errorf("create kms signer: %w", err)
	}

	signerKeyID := didKeyID

	if strings.Contains(didKeyID, "did:key") {
		res, err := didkey.New().Read(strings.Split(didKeyID, "#")[0])
		if err != nil {
			return "", err
		}

		signerKeyID = res.DIDDocument.VerificationMethod[0].ID
	} else if strings.Contains(didKeyID, "did:jwk") {
		res, err := jwk.New().Read(strings.Split(didKeyID, "#")[0])
		if err != nil {
			return "", err
		}

		signerKeyID = res.DIDDocument.VerificationMethod[0].ID
	}

	token, err := jwt.NewSigned(claims, map[string]interface{}{"typ": "JWT"}, NewJWSSigner(signerKeyID,
		string(signType), kmsSigner))
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: sign token failed: %w", err)
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: serialize token failed: %w", err)
	}

	return tokenBytes, nil
}

func (e *VPFlowExecutor) SendAuthorizedResponse(responseBody string) (time.Duration, error) {
	log.Printf("auth req: %s\n", responseBody)

	req, err := http.NewRequest(http.MethodPost, e.requestObject.RedirectURI, bytes.NewBuffer([]byte(responseBody)))
	if err != nil {
		return 0, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: e.tlsConfig}}

	st := time.Now()
	resp, err := c.Do(req)
	dur := time.Since(st)

	if err != nil {
		return dur, err
	}

	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return dur, err
	}

	if resp.StatusCode != http.StatusOK {
		return dur, fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	return dur, nil
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
