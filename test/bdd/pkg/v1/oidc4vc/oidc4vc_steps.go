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
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"golang.org/x/oauth2"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	vcsAPIGateway                       = "https://localhost:4455"
	initiateCredentialIssuanceURLFormat = vcsAPIGateway + "/issuer/profiles/%s/interactions/initiate-oidc"
	vcsAuthorizeEndpoint                = vcsAPIGateway + "/oidc/authorize"
	vcsTokenEndpoint                    = vcsAPIGateway + "/oidc/token"
	loginPageURL                        = "https://localhost:8099/login"
)

// Steps defines context for OIDC4VC scenario steps.
type Steps struct {
	bddContext          *bddcontext.BDDContext
	issuerProfile       *profileapi.Issuer
	oauthClient         *oauth2.Config // oauthClient is a public client to vcs oidc provider
	cookie              *cookiejar.Jar
	debug               bool
	initiateIssuanceURL string
	authCode            string
	accessToken         string
}

// NewSteps returns new Steps context.
func NewSteps(ctx *bddcontext.BDDContext) (*Steps, error) {
	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return nil, fmt.Errorf("init cookie jar: %w", err)
	}

	return &Steps{
		bddContext: ctx,
		cookie:     jar,
		debug:      false, // set to true to get request/response dumps
	}, nil
}

// RegisterSteps registers OIDC4VC scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^issuer has a profile set up on vcs$`, s.setupIssuerProfile)
	sc.Step(`^client is registered as a public client on vcs$`, s.registerClient)
	sc.Step(`^issuer initiates credential issuance using authorization code flow$`, s.initiateCredentialIssuance)
	sc.Step(`^initiate issuance URL is returned$`, s.checkInitiateIssuanceURL)
	sc.Step(`^client requests an authorization code using data from initiate issuance URL$`, s.getAuthorizeCode)
	sc.Step(`^user authenticates on issuer IdP$`, s.authenticateUser)
	sc.Step(`^client receives an authorization code$`, s.checkAuthorizeCode)
	sc.Step(`^client exchanges authorization code for an access token$`, s.exchangeCodeForToken)
	sc.Step(`^client receives an access token$`, s.checkAccessToken)
	sc.Step(`^client requests credential for claim data$`, s.getCredential)
	sc.Step(`^client receives a valid credential$`, s.checkCredential)
}

func (s *Steps) setupIssuerProfile() error {
	// profile is imported into vcs from the issuer profile file (./fixtures/profile/profiles.json)
	s.issuerProfile = &profileapi.Issuer{
		ID:             "issuer_oidc4vc",
		Name:           "issuer_oidc4vc",
		URL:            "http://vc-rest-echo.trustbloc.local:8075",
		Active:         true,
		OrganizationID: "test_bank",
		OIDCConfig: &profileapi.OIDC4VCConfig{ // profile is a confidential client to issuer's IdP
			ClientID:           "issuer_oidc4vc",
			ClientSecretHandle: "issuer-oidc4vc-secret",
			IssuerWellKnownURL: "https://oidc-provider.example.com:4444/.well-known/openid-configuration",
		},
		VCConfig: &profileapi.VCConfig{
			Format:                  vcsverifiable.Ldp,
			SigningAlgorithm:        vcsverifiable.JSONWebSignature2020,
			KeyType:                 kms.ECDSASecp256k1IEEEP1363,
			DIDMethod:               profileapi.OrbDIDMethod,
			SignatureRepresentation: verifiable.SignatureProofValue,
		},
		KMSConfig:  nil,
		SigningDID: nil,
		CredentialTemplates: []*profileapi.CredentialTemplate{
			{
				Contexts: []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://w3id.org/citizenship/v1",
				},
				ID:     "templateID",
				Type:   "PermanentResidentCard",
				Issuer: "issuer_oidc4vc",
			},
		},
	}

	return nil
}

func (s *Steps) registerClient() error {
	// oauth clients are imported into vcs from the oauth-clients file (./fixtures/oauth-clients/clients.json)
	s.oauthClient = &oauth2.Config{
		ClientID:    "oidc4vc_client",
		RedirectURL: "https://client.example.com/oauth/redirect",
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

	reqBody, err := json.Marshal(&initiateOIDC4VCRequest{
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

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	var initiateIssuanceResp initiateOIDC4VCResponse

	if err = json.Unmarshal(respBytes, &initiateIssuanceResp); err != nil {
		return fmt.Errorf("unmarshal initiate oidc4vc resp: %w", err)
	}

	s.initiateIssuanceURL = initiateIssuanceResp.InitiateIssuanceUrl

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

func (s *Steps) getAuthorizeCode() error {
	httpClient := &http.Client{
		Jar:       s.cookie,
		Transport: &http.Transport{TLSClientConfig: s.bddContext.TLSConfig},
	}

	if s.debug {
		httpClient.Transport = &DumpTransport{httpClient.Transport}
	}

	u, err := url.Parse(s.initiateIssuanceURL)
	if err != nil {
		return fmt.Errorf("parse initiate issuance URL: %w", err)
	}

	opState := u.Query().Get("op_state")
	state := uuid.New().String()

	resp, err := httpClient.Get(
		s.oauthClient.AuthCodeURL(state,
			oauth2.SetAuthURLParam("op_state", opState),
			oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		),
	)
	if err != nil {
		return fmt.Errorf("get auth code request: %w", err)
	}
	_ = resp.Body.Close()

	return nil
}

func (s *Steps) authenticateUser() error {
	httpClient := &http.Client{
		Jar:       s.cookie,
		Transport: &http.Transport{TLSClientConfig: s.bddContext.TLSConfig},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { // hijack redirects
			return http.ErrUseLastResponse
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

	// redirect back to third-party oidc provider after login
	resp, err = httpClient.Get(resp.Header.Get("Location"))
	if err != nil {
		return fmt.Errorf("redirect to third-party oidc provider: %w", err)
	}
	_ = resp.Body.Close()

	// redirect to consent page
	resp, err = httpClient.Get(resp.Header.Get("Location"))
	if err != nil {
		return fmt.Errorf("redirect to consent page: %w", err)
	}
	_ = resp.Body.Close()

	// redirect back to third-party oidc provider with consent verifier
	resp, err = httpClient.Get(resp.Header.Get("Location"))
	if err != nil {
		return fmt.Errorf("redirect back to auth after consent: %w", err)
	}
	_ = resp.Body.Close()

	// redirect to public vcs public /oidc/redirect
	resp, err = httpClient.Get(resp.Header.Get("Location"))
	if err != nil {
		return fmt.Errorf("redirect to public oidc redirect: %w", err)
	}
	_ = resp.Body.Close()

	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return fmt.Errorf("parse client redirect url: %w", err)
	}

	if !strings.HasPrefix(u.String(), s.oauthClient.RedirectURL) {
		return fmt.Errorf("invalid client redirect url")
	}

	s.authCode = u.Query().Get("code")

	return nil
}

func (s *Steps) checkAuthorizeCode() error {
	if s.authCode == "" {
		return fmt.Errorf("auth code is empty")
	}

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

	fmt.Printf("REQUEST:\n%s", string(reqDump))

	resp, err := d.r.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump response: %w", err)
	}

	fmt.Printf("RESPONSE:\n%s", string(respDump))

	return resp, err
}
