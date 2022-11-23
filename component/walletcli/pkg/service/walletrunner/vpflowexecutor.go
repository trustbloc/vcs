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
	"net/http"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

type VPFlowExecutor struct {
	tlsConfig           *tls.Config
	ariesServices       *AriesServices
	wallet              *wallet.Wallet
	walletToken         string
	walletDidID         string
	walletDidKeyID      string
	requestObject       *RequestObject
	requestPresentation *verifiable.Presentation
}

func (s *Service) NewVPFlowExecutor() *VPFlowExecutor {
	return &VPFlowExecutor{
		tlsConfig:      s.vcProviderConf.TLS,
		ariesServices:  s.ariesServices,
		wallet:         s.wallet,
		walletToken:    s.vcProviderConf.WalletParams.Token,
		walletDidID:    s.vcProviderConf.WalletParams.DidID,
		walletDidKeyID: s.vcProviderConf.WalletParams.DidKeyID,
	}
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

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	return nil
}

func (e *VPFlowExecutor) InitiateInteraction(url, authToken string) (*InitiateOIDC4VPResponse, error) {
	resp, err := bddutil.HTTPSDo(http.MethodPost, url, "application/json", authToken, //nolint: bodyclose
		nil, e.tlsConfig)
	if err != nil {
		return nil, err
	}
	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	result := &InitiateOIDC4VPResponse{}

	return result, json.Unmarshal(respBytes, result)
}

func (e *VPFlowExecutor) RetrieveInteractionsClaim(url, authToken string) error {
	resp, err := bddutil.HTTPSDo(http.MethodGet, url, "application/json", authToken, //nolint: bodyclose
		nil, e.tlsConfig)
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
		Exp:   time.Now().Unix() + 600,
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

func (e *VPFlowExecutor) QueryCredentialFromWallet() error {
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

func (e *VPFlowExecutor) RequestPresentation() *verifiable.Presentation {
	return e.requestPresentation
}

func (e *VPFlowExecutor) FetchRequestObject(authorizationRequest string) (string, error) {
	endpointURL := strings.TrimPrefix(authorizationRequest, "openid-vc://?request_uri=")

	resp, err := bddutil.HTTPSDo(http.MethodGet, endpointURL, "", "", nil, e.tlsConfig)
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

	return string(respBytes), nil
}
