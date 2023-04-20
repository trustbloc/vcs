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

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

type VPFlowExecutorURLs struct {
	InitiateOidcInteractionURLFormat   string
	RetrieveInteractionsClaimURLFormat string
}

type VPFlowExecutor struct {
	tlsConfig                     *tls.Config
	ariesServices                 *ariesServices
	wallet                        *wallet.Wallet
	walletToken                   string
	walletDidID                   []string
	walletDidKeyID                []string
	URLs                          *VPFlowExecutorURLs
	requestObject                 *RequestObject
	authorizationRequest          string
	transactionID                 string
	requestPresentation           []*verifiable.Presentation
	requestPresentationSubmission *presexch.PresentationSubmission
	claimsTransactionID           string
	jSONLDDocumentLoader          jsonld.DocumentLoader
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

	// This query will always return one VP - so far no plans to change this
	// We will only use this to get relevant credentials from wallet
	legacyVP, err := e.wallet.Query(e.walletToken, &wallet.QueryParams{
		Type:  "PresentationExchange",
		Query: []json.RawMessage{pdBytes},
	})
	if err != nil {
		return fmt.Errorf("failed to query credentials from wallet: %w", err)
	}

	credentials, err := e.getCredentials(legacyVP[0].Credentials())
	if err != nil {
		return fmt.Errorf("failed to parse credentials from vp: %w", err)
	}

	// New way of doing it
	vps, ps, err := e.requestObject.Claims.VPToken.PresentationDefinition.CreateVPArray(credentials, e.jSONLDDocumentLoader)
	if err != nil {
		return fmt.Errorf("failed to create VP array from selected credentials: %w", err)
	}

	e.requestPresentation = vps
	e.requestPresentationSubmission = ps

	return nil
}

func (e *VPFlowExecutor) createAuthorizedResponse() (string, error) {
	idToken := &IDTokenClaims{
		VPToken: IDTokenVPToken{
			PresentationSubmission: e.requestPresentationSubmission,
		},
		Nonce: e.requestObject.Nonce,
		Exp:   time.Now().Unix() + 600,
		Iss:   "https://self-issued.me/v2/openid-vc",
	}

	idTokenJWS, err := signToken(idToken, e.walletDidKeyID[0], e.ariesServices.crypto, e.ariesServices.kms)
	if err != nil {
		return "", fmt.Errorf("sign id_token: %w", err)
	}

	var tokens []string

	for _, vp := range e.requestPresentation {
		did, err := e.getSubjectID(vp.Credentials())
		if err != nil {
			return "", err
		}

		didIndex := e.getDIDIndex(did)

		vpToken := VPTokenClaims{
			VP:    vp,
			Nonce: e.requestObject.Nonce,
			Exp:   time.Now().Unix() + 600,
			Iss:   did,
		}

		vpTokenJWS, err := signToken(vpToken, e.walletDidKeyID[didIndex], e.ariesServices.crypto, e.ariesServices.kms)
		if err != nil {
			return "", fmt.Errorf("sign vp_token: %w", err)
		}

		tokens = append(tokens, vpTokenJWS)
	}

	tokensJSON := tokens[0]

	if len(tokens) > 1 {
		tokensJSONBytes, err := json.Marshal(tokens)
		if err != nil {
			return "", fmt.Errorf("marshal tokens: %w", err)
		}

		tokensJSON = string(tokensJSONBytes)
	}

	return fmt.Sprintf("id_token=%s&vp_token=%s&state=%s", idTokenJWS, tokensJSON, e.requestObject.State), nil
}

func (e *VPFlowExecutor) getDIDIndex(did string) int {
	for index, walletDID := range e.walletDidID {
		if did == walletDID {
			return index
		}
	}

	return -1
}

func (e *VPFlowExecutor) getSubjectID(creds []interface{}) (string, error) {
	subjectIDMap := make(map[string]bool)

	var subjectID string

	for _, cred := range creds {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return "", err
		}

		vc, err := verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(e.jSONLDDocumentLoader))
		if err != nil {
			return "", fmt.Errorf("fail to parse credential: %w", err)
		}

		subjectID, err = verifiable.SubjectID(vc.Subject)
		if err != nil {
			return "", fmt.Errorf("failed to get subject ID: %w", err)
		}

		if vc.JWT != "" {
			// We use this strange code, because cred.JWTClaims(false) not take to account "sub" claim from jwt
			credToken, credErr := jwt.Parse(vc.JWT, jwt.WithSignatureVerifier(&noVerifier{}))
			if credErr != nil {
				return "", fmt.Errorf("fail to parse credential as jwt: %w", credErr)
			}

			subjectID = fmt.Sprint(credToken.Payload["sub"])
		}

		subjectIDMap[subjectID] = true
	}

	if len(subjectIDMap) > 1 {
		fmt.Println("WARNING ... more than one subject ID found in VP")
	}

	return subjectID, nil
}

func (e *VPFlowExecutor) getCredentials(creds []interface{}) ([]*verifiable.Credential, error) {
	var credentials []*verifiable.Credential

	for _, cred := range creds {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}

		vc, err := verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(e.jSONLDDocumentLoader))
		if err != nil {
			return nil, fmt.Errorf("fail to parse credential: %w", err)
		}

		credentials = append(credentials, vc)
	}

	return credentials, nil
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

func (e *VPFlowExecutor) retrieveInteractionsClaim(txID, authToken string, status int) error {
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

	if resp.StatusCode != status {
		return bddutil.ExpectedStatusCodeError(status, resp.StatusCode, respBytes)
	}

	return nil
}

type jwtVCClaims struct {
	Sub string `json:"sub"`
}

// noVerifier is used when no JWT signature verification is needed.
// To be used with precaution.
type noVerifier struct{}

func (v noVerifier) Verify(_ jose.Headers, _, _, _ []byte) error {
	return nil
}
