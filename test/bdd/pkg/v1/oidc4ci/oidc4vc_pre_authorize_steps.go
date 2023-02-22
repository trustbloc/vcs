/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cucumber/godog"
	"github.com/samber/lo"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/credentialoffer"
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
	credential              interface{}
	oauthClient             *oauth2.Config
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

	sc.Step(`^issuer sends request to initiate-issuance with requirePin "([^"]*)"$`, s.initiateIssuance)
	sc.Step(`^issuer receives response with oidc url`, s.parseUrl)
	sc.Step(`^issuer represent this url to client as qrcode$`, s.parseUrl)

	sc.Step(`^client scans qrcode$`, s.parseUrl)
	sc.Step(`^client should receive access token for further interactions with vc api$`, s.receiveToken)

	sc.Step(`^client requests credential for claim data with pre-authorize flow$`, s.getCredential)
	sc.Step(`^client receives a valid credential with pre-authorize flow$`, s.checkCredential)

	sc.Step(`^claim data are removed from the database$`, s.checkClaimData)
}

func (s *PreAuthorizeStep) parseUrl() error {
	if !strings.HasPrefix(s.initiateResponse.OfferCredentialURL, "openid-credential-offer://") {
		return fmt.Errorf("invalid prefix for initiateUrl. got %v", s.initiateResponse.OfferCredentialURL)
	}

	offerResponse, err := credentialoffer.ParseInitiateIssuanceUrl(s.initiateResponse.OfferCredentialURL, s.httpClient)
	if err != nil {
		return fmt.Errorf("parse initiate issuance URL: %w", err)
	}

	resp, err := s.httpClient.Get(fmt.Sprintf("%s/.well-known/openid-configuration", offerResponse.CredentialIssuer))
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
	s.preAuthorizeCode = offerResponse.Grants.PreAuthorizationGrant.PreAuthorizedCode
	s.preAuthorizePinRequired = strconv.FormatBool(offerResponse.Grants.PreAuthorizationGrant.UserPinRequired)

	return nil
}

func (s *PreAuthorizeStep) receiveToken() error {
	val := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {s.preAuthorizeCode},
	}

	if s.preAuthorizePinRequired == "true" {
		val.Add("user_pin", *s.initiateResponse.UserPin)
	}

	resp, err := s.httpClient.PostForm(s.preAuthorizeUrl, val)
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

	accessToken, err := bddutil.IssueAccessToken(context.Background(), oidcProviderURL,
		issuer.OrganizationID, "ejqxi9jb1vew2jbdnogpjcgrz", []string{"org_admin"})
	if err != nil {
		return err
	}

	s.issuer = issuer
	s.bddContext.Args[getOrgAuthTokenKey(issuer.OrganizationID)] = accessToken

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

func (s *PreAuthorizeStep) initiateIssuance(requirePin string) error {
	issuanceURL := fmt.Sprintf(initiateCredentialIssuanceURLFormat, s.issuer.ID)
	token := s.bddContext.Args[getOrgAuthTokenKey(s.issuer.OrganizationID)]

	req := &initiateOIDC4CIRequest{
		ClaimData: lo.ToPtr(map[string]interface{}{
			"familyName":   "John Doe",
			"givenName":    "John",
			"degree":       "MIT",
			"degreeSchool": "MIT school",
		}),
		CredentialTemplateId: "templateID",
		GrantType:            "authorization_code",
		Scope:                []string{"openid", "profile"},
	}
	if strings.EqualFold(requirePin, "true") {
		req.UserPinRequired = lo.ToPtr(true)
	}

	reqBody, err := json.Marshal(req)
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

func (s *PreAuthorizeStep) getCredential() error {
	cred, err := getCredential(s.oauthClient, (&oauth2.Token{
		AccessToken: s.tokenResponse.AccessToken,
	}).WithExtra(map[string]interface{}{
		"c_nonce": *s.tokenResponse.CNonce,
	}), s.bddContext.TLSConfig, false)
	if err != nil {
		return err
	}

	s.credential = cred.Credential
	return nil
}

func (s *PreAuthorizeStep) checkCredential() error {
	if s.credential == nil {
		return fmt.Errorf("credential is empty")
	}

	return nil
}

func (s *PreAuthorizeStep) checkClaimData() error {
	if err := s.getCredential(); err != nil {
		if strings.Contains(err.Error(), "get claim data: data not found") {
			return nil
		}

		return err
	}

	return errors.New("claim data found")
}
