/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"
	"github.com/samber/lo"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

type PreAuthorizeStep struct {
	bddContext              *bddcontext.BDDContext
	issuer                  *profileapi.Issuer
	httpClient              *http.Client
	initiateResponse        *initiateOIDC4CIResponse
	preAuthorizeUrl         string
	preAuthorizeCode        string
	preAuthorizePinRequired string
	tokenResponse           *accessTokenResponse
}

func NewPreAuthorizeStep(ctx *bddcontext.BDDContext) *PreAuthorizeStep {
	return &PreAuthorizeStep{
		bddContext: ctx,
		httpClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: ctx.TLSConfig},
		},
	}
}

func (s *PreAuthorizeStep) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^issuer with id "([^"]*)" wants to issue credentials to his client with pre-auth code flow$`, s.prepareIssuer)

	sc.Step(`^issuer sends request to initiate-issuance$`, s.initiateIssuance)
	sc.Step(`^issuer receives response with oidc url`, s.parseUrl)
	sc.Step(`^issuer represent this url to client as qrcode$`, s.parseUrl)

	sc.Step(`^client scans qrcode$`, s.parseUrl)
	sc.Step(`^client should receive access token for further interactions with vc api$`, s.receiveToken)
}

func (s *PreAuthorizeStep) parseUrl() error {
	if !strings.HasPrefix(s.initiateResponse.InitiateIssuanceUrl, "openid-initiate-issuance://") {
		return fmt.Errorf("invalid prefix for initiateUrl. got %v", s.initiateResponse.InitiateIssuanceUrl)
	}

	parsed, err := url.Parse(s.initiateResponse.InitiateIssuanceUrl)
	if err != nil {
		return err
	}

	issuerUrl := parsed.Query().Get("issuer")

	resp, err := s.httpClient.Get(fmt.Sprintf("%s/.well-known/openid-configuration", issuerUrl))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code for well-known. got %v", resp.StatusCode)
	}

	var cfg issuer.WellKnownOpenIDConfiguration
	if err = json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return err
	}

	s.preAuthorizeUrl = cfg.TokenEndpoint
	s.preAuthorizeCode = parsed.Query().Get("pre-authorized_code")
	s.preAuthorizePinRequired = parsed.Query().Get("user_pin_required")

	if s.preAuthorizePinRequired == "true" {
		return fmt.Errorf("pin required should be false")
	}

	return nil
}

func (s *PreAuthorizeStep) receiveToken() error {
	resp, err := s.httpClient.PostForm(s.preAuthorizeUrl, url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {s.preAuthorizeCode},
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %v", resp.StatusCode)
	}

	var token accessTokenResponse
	if err = json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return err
	}

	if len(token.AccessToken) == 0 {
		return fmt.Errorf("invalid token")
	}

	s.tokenResponse = &token

	return nil
}

func (s *PreAuthorizeStep) prepareIssuer(id string) error {
	issuer, ok := s.bddContext.IssuerProfiles[id]
	if !ok {
		return fmt.Errorf("issuer profile '%s' not found", id)
	}

	if issuer.OIDCConfig == nil {
		return fmt.Errorf("oidc config not set for issuer profile '%s'", id)
	}

	accessToken, err := bddutil.IssueAccessToken(context.Background(), oidcProviderURL,
		issuer.OrganizationID, "test-org-secret", []string{"org_admin"})
	if err != nil {
		return err
	}

	s.issuer = issuer
	s.bddContext.Args[getOrgAuthTokenKey(issuer.OrganizationID)] = accessToken

	return nil
}

func (s *PreAuthorizeStep) initiateIssuance() error {
	issuanceURL := fmt.Sprintf(initiateCredentialIssuanceURLFormat, s.issuer.ID)
	token := s.bddContext.Args[getOrgAuthTokenKey(s.issuer.OrganizationID)]

	reqBody, err := json.Marshal(&initiateOIDC4CIRequest{
		ClaimData: lo.ToPtr(map[string]interface{}{
			"claim1": "value1",
			"claim2": "value2",
		}),
		CredentialTemplateId: "templateID",
		GrantType:            "authorization_code",
		Scope:                []string{"openid", "profile"},
	})
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPSDo(http.MethodPost, issuanceURL, "application/json", token, bytes.NewReader(reqBody),
		s.bddContext.TLSConfig)
	if err != nil {
		return fmt.Errorf("https do: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code %v", resp.StatusCode)
	}

	var oidcInitiateResponse initiateOIDC4CIResponse
	if err = json.NewDecoder(resp.Body).Decode(&oidcInitiateResponse); err != nil {
		return err
	}

	s.initiateResponse = &oidcInitiateResponse

	return nil
}
