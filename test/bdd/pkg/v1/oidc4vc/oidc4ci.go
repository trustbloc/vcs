/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/credentialoffer"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

const (
	vcsAPIGateway                       = "https://api-gateway.trustbloc.local:5566"
	initiateCredentialIssuanceURLFormat = vcsAPIGateway + "/issuer/profiles/%s/interactions/initiate-oidc"
	vcsAuthorizeEndpoint                = vcsAPIGateway + "/oidc/authorize"
	vcsTokenEndpoint                    = vcsAPIGateway + "/oidc/token"
	oidcProviderURL                     = "http://cognito-mock.trustbloc.local:9229/local_5a9GzRvB"
	loginPageURL                        = "https://localhost:8099/login"
)

func (s *Steps) authorizeIssuer(id string) error {
	issuer, ok := s.bddContext.IssuerProfiles[id]
	if !ok {
		return fmt.Errorf("issuer profile '%s' not found", id)
	}

	if issuer.OIDCConfig == nil {
		return fmt.Errorf("oidc config not set for issuer profile '%s'", id)
	}

	accessToken, err := bddutil.IssueAccessToken(context.Background(), oidcProviderURL,
		issuer.OrganizationID, "ejqxi9jb1vew2jbdnogpjcgrz", []string{"org_admin"})
	if err != nil {
		return err
	}

	s.issuerProfile = issuer
	s.bddContext.Args[getOrgAuthTokenKey(issuer.OrganizationID)] = accessToken

	return nil
}

func (s *Steps) registerPublicClient() error {
	// TODO: Implement API to register public clients to vcs oidc or add support for dynamic client registration.
	// for now, oauth clients are imported into vcs from the file (./fixtures/oauth-clients/clients.json)
	s.oauthClient = &oauth2.Config{
		ClientID:    "oidc4vc_client",
		RedirectURL: "http://127.0.0.1/callback",
		Scopes:      []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   vcsAuthorizeEndpoint,
			TokenURL:  vcsTokenEndpoint,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	return nil
}

func (s *Steps) initiateCredentialIssuance() error {
	endpointURL := fmt.Sprintf(initiateCredentialIssuanceURLFormat, s.issuerProfile.ID)
	token := s.bddContext.Args[getOrgAuthTokenKey(s.issuerProfile.OrganizationID)]

	reqBody, err := json.Marshal(&initiateOIDC4CIRequest{
		CredentialTemplateId: "templateID",
		GrantType:            "authorization_code",
		OpState:              uuid.New().String(),
		ResponseType:         "code",
		Scope:                []string{"openid", "profile"},
	})
	if err != nil {
		return fmt.Errorf("marshal initiate oidc4vc req: %w", err)
	}

	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", token, bytes.NewReader(reqBody),
		s.bddContext.TLSConfig)
	if err != nil {
		return fmt.Errorf("https do: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	fmt.Println(string(b))

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, b)
	}

	var r initiateOIDC4CIResponse

	if err = json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("unmarshal initiate oidc4vc resp: %w", err)
	}

	s.initiateIssuanceURL = r.OfferCredentialURL

	return nil
}

func (s *Steps) checkInitiateIssuanceURL() error {
	if s.initiateIssuanceURL == "" {
		return fmt.Errorf("initiate issuance URL is empty")
	}

	if _, err := url.Parse(s.initiateIssuanceURL); err != nil {
		return fmt.Errorf("parse initiate issuance URL: %w", err)
	}

	return nil
}

func (s *Steps) initiateOIDCCredentialIssuance() error {
	// Get authorization code using data from initiate issuance URL
	err := s.getAuthCode()
	if err != nil {
		return fmt.Errorf("getAuthCode failed: %w", err)
	}

	// Authenticates Profile user on Issuer IdP
	err = s.authenticateUser()
	if err != nil {
		return fmt.Errorf("authenticateUser failed: %w", err)
	}

	// Exchange authorization code for access token
	err = s.exchangeCodeForToken()
	if err != nil {
		return fmt.Errorf("exchangeCodeForToken failed: %w", err)
	}

	return nil
}

func (s *Steps) getAuthCode() error {
	httpClient := &http.Client{
		Jar:       s.cookie,
		Transport: &http.Transport{TLSClientConfig: s.bddContext.TLSConfig},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), s.oauthClient.RedirectURL) {
				s.authCode = req.URL.Query().Get("code")

				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	if s.debug {
		httpClient.Transport = &DumpTransport{httpClient.Transport}
	}

	offerResponse, err := credentialoffer.ParseInitiateIssuanceUrl(s.initiateIssuanceURL, httpClient)
	if err != nil {
		return fmt.Errorf("parse initiate issuance URL: %w", err)
	}

	state := uuid.New().String()

	resp, err := httpClient.Get(
		s.oauthClient.AuthCodeURL(state,
			oauth2.SetAuthURLParam("issuer_state", offerResponse.Grants.AuthorizationCode.IssuerState),
			oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("authorization_details", `{"type":"openid_credential","types":["VerifiableCredential","VerifiedEmployee"],"format":"jwt_vc_json-ld"}`), //nolint:lll
		),
	)
	if err != nil {
		return fmt.Errorf("get auth code request: %w", err)
	}
	_ = resp.Body.Close()

	return nil
}

func (s *Steps) authenticateUser() error {
	if s.authCode != "" {
		return nil
	}

	httpClient := &http.Client{
		Jar:       s.cookie,
		Transport: &http.Transport{TLSClientConfig: s.bddContext.TLSConfig},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), s.oauthClient.RedirectURL) {
				s.authCode = req.URL.Query().Get("code")

				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	if s.debug {
		httpClient.Transport = &DumpTransport{httpClient.Transport}
	}

	// authenticate user
	resp, err := httpClient.Post(loginPageURL, "", http.NoBody)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	return nil
}

func (s *Steps) exchangeCodeForToken() error {
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: s.bddContext.TLSConfig},
	}

	if s.debug {
		httpClient.Transport = &DumpTransport{httpClient.Transport}
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

	token, err := s.oauthClient.Exchange(ctx, s.authCode,
		oauth2.SetAuthURLParam("code_verifier", "xalsLDydJtHwIQZukUyj6boam5vMUaJRWv-BnGCAzcZi3ZTs"),
	)
	if err != nil {
		return fmt.Errorf("exchange code for token: %w", err)
	}

	s.accessToken = token.AccessToken

	return nil
}

func (s *Steps) checkAccessToken() error {
	if s.accessToken == "" {
		return fmt.Errorf("access token is empty")
	}

	return nil
}

func (s *Steps) getCredential() error {
	return fmt.Errorf("not implemented")
}

func (s *Steps) checkCredential() error {
	return fmt.Errorf("not implemented")
}

func getOrgAuthTokenKey(org string) string {
	return org + "-accessToken"
}

// DumpTransport is http.RoundTripper that dumps request/response.
type DumpTransport struct {
	r http.RoundTripper
}

// RoundTrip implements the RoundTripper interface.
func (d *DumpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump request: %w", err)
	}

	fmt.Printf("REQUEST:\n%s\n", string(reqDump))

	resp, err := d.r.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump response: %w", err)
	}

	fmt.Printf("RESPONSE:\n%s\n", string(respDump))

	return resp, err
}
