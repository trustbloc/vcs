/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

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
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

type VPFlowExecutorURLs struct {
	InitiateOidcInteractionURLFormat   string
	RetrieveInteractionsClaimURLFormat string
}

type VPFlowExecutor struct {
	tlsConfig            *tls.Config
	ariesServices        *ariesServices
	wallet               *wallet.Wallet
	walletToken          string
	walletDidID          string
	walletDidKeyID       string
	URLs                 *VPFlowExecutorURLs
	requestObject        *RequestObject
	authorizationRequest string
	transactionID        string
	requestPresentation  *verifiable.Presentation
}

func (e *VPFlowExecutor) initiateInteraction(profileName, authToken string) error {
	endpointURL := fmt.Sprintf(e.URLs.InitiateOidcInteractionURLFormat, profileName)

	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", authToken, //nolint: bodyclose
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

	result := &initiateOIDC4VPResponse{}

	err = json.Unmarshal(respBytes, result)
	if err != nil {
		return err
	}

	e.authorizationRequest = result.AuthorizationRequest
	e.transactionID = result.TxId

	return nil
}

func (e *VPFlowExecutor) fetchRequestObject() (string, error) {
	endpointURL := strings.TrimPrefix(e.authorizationRequest, "openid-vc://?request_uri=")

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

func (e *VPFlowExecutor) verifyAuthorizationRequestAndDecodeClaims(rawRequestObject string) error {
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

func (e *VPFlowExecutor) queryCredentialFromWallet() error {
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

	for _, c := range vps[0].Credentials() {
		credential, ok := c.(*verifiable.Credential)
		if !ok {
			continue
		}

		//TODO: this condition must be gone once AFGO will properly support Marshal/Unmarshal SDJWT credential.
		if credential.JWT != "" && len(credential.SDJWTDisclosures) > 0 {
			// Creating Combined Format for Presentation from credential assuming that
			// wallet.Query() returned only those disclosures, that must be disclosed according to query.
			sdjwt, err := credential.MarshalWithDisclosure(verifiable.DiscloseAll())
			if err != nil {
				continue
			}

			sdjwt = strings.TrimSuffix(sdjwt, "~")

			credential.JWT = sdjwt
		}
	}

	e.requestPresentation = vps[0]

	return nil
}

func (e *VPFlowExecutor) createAuthorizedResponse() (string, error) {
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

func (e *VPFlowExecutor) sendAuthorizedResponse(responseBody string) error {
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

func (e *VPFlowExecutor) retrieveInteractionsClaim(txID, authToken string) error {
	endpointURL := fmt.Sprintf(e.URLs.RetrieveInteractionsClaimURLFormat, txID)
	resp, err := bddutil.HTTPSDo(http.MethodGet, endpointURL, "application/json", authToken, //nolint: bodyclose
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
