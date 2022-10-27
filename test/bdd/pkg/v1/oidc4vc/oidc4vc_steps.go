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
	vcsAPIHost                          = "https://localhost:8070"
	vcsPublicAuthURL                    = vcsAPIHost + "/oidc/authorize"
	vcsPublicTokenURL                   = vcsAPIHost + "/oidc/token"
	initiateCredentialIssuanceURLFormat = vcsAPIHost + "/issuer/profiles/%s/interactions/initiate-oidc"
)

// Steps defines context for OIDC4VC scenario steps.
type Steps struct {
	bddContext          *bddcontext.BDDContext
	issuerProfile       *profileapi.Issuer
	oauthClient         *oauth2.Config
	initiateIssuanceURL string
	authCode            string
	accessToken         string
}

// NewSteps returns new Steps context.
func NewSteps(ctx *bddcontext.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers OIDC4VC scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^issuer has a profile set up on vcs$`, s.setIssuerProfile)
	sc.Step(`^issuer initiates credential issuance using authorization code flow$`, s.initiateCredentialIssuance)
	sc.Step(`^initiate issuance URL is returned$`, s.checkInitiateIssuanceURL)
	sc.Step(`^client requests an authorization code using data from initiate issuance URL$`, s.getAuthorizeCode)
	sc.Step(`^client receives an authorization code$`, s.checkAuthorizeCode)
	sc.Step(`^client exchanges authorization code for an access token$`, s.exchangeCodeForToken)
	sc.Step(`^client receives an access token$`, s.checkAccessToken)
	sc.Step(`^client requests credential for claim data$`, s.getCredential)
	sc.Step(`^client receives a valid credential$`, s.checkCredential)
}

func (s *Steps) setIssuerProfile() error {
	s.issuerProfile = &profileapi.Issuer{
		ID:             "issuer_oidc4vc",
		Name:           "issuer_oidc4vc",
		URL:            "http://vc-rest-echo.trustbloc.local:8075",
		Active:         true,
		OrganizationID: "test_org",
		OIDCConfig: &profileapi.OIDC4VCConfig{
			ClientID:           "issuer_oidc4vc",
			ClientSecretHandle: "issuer-oidc4vc-secret",
			IssuerWellKnownURL: "https://oidc-provider.example.com:4445/.well-known/openid-configuration",
		},
		VCConfig: &profileapi.VCConfig{
			Format:                  vcsverifiable.Ldp,
			SigningAlgorithm:        vcsverifiable.JSONWebSignature2020,
			KeyType:                 kms.ECDSASecp256k1IEEEP1363,
			DIDMethod:               profileapi.OrbDIDMethod,
			SignatureRepresentation: verifiable.SignatureProofValue,
		},
		KMSConfig:           nil,
		SigningDID:          nil,
		CredentialTemplates: nil, // TODO: Set credential template
	}

	return nil
}

func (s *Steps) initiateCredentialIssuance() error {
	endpointURL := fmt.Sprintf(initiateCredentialIssuanceURLFormat, s.issuerProfile.Name)
	token := s.bddContext.Args[getOrgAuthTokenKey(s.issuerProfile.OrganizationID)]

	reqBody, err := json.Marshal(&initiateOIDC4VCRequest{
		CredentialTemplateId: "",
		GrantType:            "authorization_code",
		OpState:              uuid.New().String(),
		ResponseType:         "code",
		Scope:                []string{"openid"},
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

	if resp.StatusCode != http.StatusCreated {
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	var r initiateOIDC4VCResponse

	if err = json.Unmarshal(respBytes, &r); err != nil {
		return fmt.Errorf("unmarshal initiate oidc4vc resp: %w", err)
	}

	s.initiateIssuanceURL = r.InitiateIssuanceUrl

	return nil
}

func (s *Steps) checkInitiateIssuanceURL() error {
	if s.initiateIssuanceURL == "" {
		return fmt.Errorf("initiate issuance URL is empty")
	}

	return nil
}

func (s *Steps) getAuthorizeCode() error {
	s.oauthClient = &oauth2.Config{
		ClientID:     s.issuerProfile.OIDCConfig.ClientID,
		ClientSecret: s.issuerProfile.OIDCConfig.ClientSecretHandle,
		RedirectURL:  vcsAPIHost + "/oidc/callback",
		Scopes:       []string{"openid"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   vcsPublicAuthURL,
			TokenURL:  vcsPublicTokenURL,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return fmt.Errorf("failed to init cookie jar: %w", err)
	}

	httpClient := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: s.bddContext.TLSConfig},
	}

	state := uuid.New().String()
	nonce := uuid.New().String()

	resp, err := httpClient.Get(s.oauthClient.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce)))
	if err != nil {
		return fmt.Errorf("failed to get auth code: %w", err)
	}

	q := resp.Request.URL.Query()

	if state != q.Get("state") {
		return fmt.Errorf("state mismatch")
	}

	s.authCode = q.Get("code")

	return nil
}

func (s *Steps) checkAuthorizeCode() error {
	if s.authCode == "" {
		return fmt.Errorf("auth code is empty")
	}

	return nil
}

func (s *Steps) exchangeCodeForToken() error {
	token, err := s.oauthClient.Exchange(context.Background(), s.authCode)
	if err != nil {
		return fmt.Errorf("failed to exchange code for token: %w", err)
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
