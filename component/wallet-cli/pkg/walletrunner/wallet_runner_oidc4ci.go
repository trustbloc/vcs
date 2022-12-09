/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/samber/lo"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/kms/signer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

type OIDC4CIConfig struct {
	InitiateIssuanceURL string
	ClientID            string
	Scope               []string
	RedirectURI         string
	CredentialType      string
	CredentialFormat    string
	Pin                 string
	Login               string
	Password            string
}

func (s *Service) RunOIDC4CI(config *OIDC4CIConfig) error {
	log.Println("Starting OIDC4VCI authorized code flow")

	log.Printf("Initiate issuance URL:\n\n\t%s\n\n", config.InitiateIssuanceURL)
	initiateIssuanceURL, err := url.Parse(config.InitiateIssuanceURL)
	if err != nil {
		return fmt.Errorf("parse initiate issuance url: %w", err)
	}

	s.print("Getting issuer OIDC config")
	oidcConfig, err := s.getIssuerOIDCConfig(initiateIssuanceURL.Query().Get("issuer"))
	if err != nil {
		return fmt.Errorf("get issuer oidc config: %w", err)
	}

	s.oauthClient = &oauth2.Config{
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

	b, err := json.Marshal(&common.AuthorizationDetails{
		Type:           "openid_credential",
		CredentialType: config.CredentialType,
		Format:         lo.ToPtr(config.CredentialFormat),
	})
	if err != nil {
		return fmt.Errorf("marshal authorization details: %w", err)
	}

	authCodeURL := s.oauthClient.AuthCodeURL(state,
		oauth2.SetAuthURLParam("op_state", opState),
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("authorization_details", string(b)),
	)

	var authCode string

	if config.Login != "" {
		authCode, err = s.getAuthCode(config, authCodeURL)
	} else {
		authCode, err = s.getAuthCodeFromBrowser(authCodeURL)
	}

	if authCode == "" {
		return fmt.Errorf("auth code is empty")
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, s.httpClient)

	s.print("Exchanging authorization code for access token")
	token, err := s.oauthClient.Exchange(ctx, authCode,
		oauth2.SetAuthURLParam("code_verifier", "xalsLDydJtHwIQZukUyj6boam5vMUaJRWv-BnGCAzcZi3ZTs"),
	)
	if err != nil {
		return fmt.Errorf("exchange code for token: %w", err)
	}

	s.token = token

	err = s.CreateWallet()
	if err != nil {
		return fmt.Errorf("create wallet: %w", err)
	}

	s.print("Getting credential")
	vc, err := s.getCredential(oidcConfig.CredentialEndpoint, config.CredentialType, config.CredentialFormat)
	if err != nil {
		return fmt.Errorf("get credential: %w", err)
	}

	b, err = json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("marshal vc: %w", err)
	}

	s.print("Adding credential to wallet")
	if err = s.wallet.Add(s.vcProviderConf.WalletParams.Token, wallet.Credential, b); err != nil {
		return fmt.Errorf("add credential: %w", err)
	}

	log.Printf("Credential with type [%v] added successfully", config.CredentialType)

	s.wallet.Close()

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

func (s *Service) getAuthCode(config *OIDC4CIConfig, authCodeURL string) (string, error) {
	var loginURL, consentURL *url.URL
	var authCode string

	httpClient := &http.Client{
		Jar:       s.httpClient.Jar,
		Transport: s.httpClient.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// intercept login request
			if strings.Contains(req.URL.String(), "/login?login_challenge=") {
				loginURL = req.URL

				return http.ErrUseLastResponse
			}

			// intercept consent request
			if strings.Contains(req.URL.String(), "/consent?consent_challenge=") {
				consentURL = req.URL

				return http.ErrUseLastResponse
			}

			// intercept client auth code
			if strings.HasPrefix(req.URL.String(), config.RedirectURI) {
				authCode = req.URL.Query().Get("code")

				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	s.print("Getting authorization code")
	resp, err := httpClient.Get(authCodeURL)
	if err != nil {
		return "", fmt.Errorf("get auth code: %w", err)
	}
	_ = resp.Body.Close()

	if loginURL == nil {
		return "", fmt.Errorf("login URL is empty")
	}

	s.print(fmt.Sprintf("Authenticating user as [%s]", config.Login))
	resp, err = httpClient.PostForm(loginURL.String(),
		url.Values{
			"challenge": loginURL.Query()["login_challenge"],
			"email":     {config.Login},
			"password":  {config.Password},
		},
	)
	if err != nil {
		return "", fmt.Errorf("post login: %w", err)
	}
	_ = resp.Body.Close()

	if consentURL == nil {
		return "", fmt.Errorf("consent URL is empty")
	}

	s.print("Getting user consent [accept]")
	resp, err = httpClient.PostForm(consentURL.String(),
		url.Values{
			"challenge": loginURL.Query()["consent_challenge"],
			"submit":    {"accept"},
		},
	)
	if err != nil {
		return "", fmt.Errorf("post consent: %w", err)
	}
	_ = resp.Body.Close()

	return authCode, nil
}

func (s *Service) getAuthCodeFromBrowser(authCodeURL string) (string, error) {
	log.Printf("Login with a browser:\n\n%s\n\n", authCodeURL)
	log.Println("Enter auth code:")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text(), nil
}

func (s *Service) getCredential(credentialEndpoint, credentialType, credentialFormat string) (interface{}, error) {
	km := s.ariesServices.KMS()
	cr := s.ariesServices.Crypto()

	didKeyID := s.vcProviderConf.WalletParams.DidKeyID

	kmsSigner, err := signer.NewKMSSigner(km, cr, didKeyID, "ES384", nil)
	if err != nil {
		return nil, fmt.Errorf("create kms signer: %w", err)
	}

	claims := &JWTProofClaims{
		Issuer:   s.oauthClient.ClientID,
		IssuedAt: time.Now().Unix(),
		Nonce:    s.token.Extra("c_nonce").(string),
	}

	signedJWT, err := jwt.NewSigned(claims, nil, NewJWSSigner(didKeyID, "ES384", kmsSigner))
	if err != nil {
		return nil, fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return nil, fmt.Errorf("serialize signed jwt: %w", err)
	}

	b, err := json.Marshal(CredentialRequest{
		DID:    s.vcProviderConf.WalletParams.DidID,
		Format: credentialFormat,
		Type:   credentialType,
		Proof: JWTProof{
			ProofType: "jwt",
			JWT:       jws,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal credential request: %w", err)
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, s.httpClient)

	httpClient := s.oauthClient.Client(ctx, s.token)

	resp, err := httpClient.Post(credentialEndpoint, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, fmt.Errorf("get credential: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get credential: status %s", resp.Status)
	}

	var credentialResp CredentialResponse

	if err = json.NewDecoder(resp.Body).Decode(&credentialResp); err != nil {
		return nil, fmt.Errorf("decode credential response: %w", err)
	}

	return credentialResp.Credential, nil
}

func (s *Service) print(msg string) {
	if s.debug {
		fmt.Println()
	}

	log.Printf("%s\n\n", msg)
}
