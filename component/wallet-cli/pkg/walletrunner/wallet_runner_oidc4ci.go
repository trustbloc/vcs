/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

type OIDC4CIConfig struct {
	InitiateIssuanceURL string
	ClientID            string
	Scope               []string
	RedirectURI         string
}

func (s *Service) RunOIDC4CI(config *OIDC4CIConfig) error {
	log.Println("Start OIDC4CI authorized code flow")

	log.Println("Creating wallet")
	err := s.CreateWallet()
	if err != nil {
		return fmt.Errorf("create wallet: %w", err)
	}

	log.Printf("Initiate issuance URL: %s\n", config.InitiateIssuanceURL)

	initiateIssuanceURL, err := url.Parse(config.InitiateIssuanceURL)
	if err != nil {
		return fmt.Errorf("parse initiate issuance url: %w", err)
	}

	log.Println("Getting issuer OIDC config from well-known endpoint")
	oidcConfig, err := s.getIssuerOIDCConfig(initiateIssuanceURL.Query().Get("issuer"))
	if err != nil {
		return fmt.Errorf("get issuer oidc config: %w", err)
	}
	log.Printf("Issuer OIDC config:\n%+v\n", oidcConfig)

	log.Println("Creating oauth2 client")
	oauthClient := &oauth2.Config{
		ClientID:    config.ClientID,
		RedirectURL: config.RedirectURI,
		Scopes:      config.Scope,
		Endpoint: oauth2.Endpoint{
			AuthURL:   oidcConfig.AuthorizationEndpoint,
			TokenURL:  oidcConfig.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	opState := initiateIssuanceURL.Query().Get("op_state")
	state := uuid.New().String()

	log.Println("Getting authorization code")
	authResp, err := s.httpClient.Get(
		oauthClient.AuthCodeURL(state,
			oauth2.SetAuthURLParam("op_state", opState),
			oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("authorization_details", `{"type":"openid_credential","credential_type":"PermanentResidentCard","format":"ldp_vc"}`), //nolint:lll
		),
	)
	if err != nil {
		return fmt.Errorf("get auth code request: %w", err)
	}

	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusOK {
		return fmt.Errorf("get authorization code: status code %d", authResp.StatusCode)
	}

	// TODO: Add steps for the rest of the flow

	return nil
}

func (s *Service) getIssuerOIDCConfig(issuerURL string) (*issuerv1.WellKnownOpenIDConfiguration, error) {
	// GET /issuer/{profileID}/.well-known/openid-configuration
	resp, err := s.httpClient.Get(issuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("get issuer well-known: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get issuer well-known: status code %d", resp.StatusCode)
	}

	var oidcConfig issuerv1.WellKnownOpenIDConfiguration

	if err = json.NewDecoder(resp.Body).Decode(&oidcConfig); err != nil {
		return nil, fmt.Errorf("decode issuer well-known: %w", err)
	}

	return &oidcConfig, nil
}
