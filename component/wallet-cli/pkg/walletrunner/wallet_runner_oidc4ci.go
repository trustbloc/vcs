/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
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
	LoginURL            string
	CredentialType      string
	CredentialFormat    string
	Interactive         bool
	Pin                 string
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

	log.Println("Getting authorization code")
	authResp, err := s.httpClient.Get(
		s.oauthClient.AuthCodeURL(state,
			oauth2.SetAuthURLParam("op_state", opState),
			oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("authorization_details", string(b)),
		),
	)
	if err != nil {
		return fmt.Errorf("get auth code request: %w", err)
	}

	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusOK {
		return fmt.Errorf("get authorization code: status code %d", authResp.StatusCode)
	}

	var authCode string

	if config.Interactive {
		// TODO: Implement support for interactive login/consent
	} else {
		authCode, err = s.getAuthCodeNonInteractive(config.LoginURL)
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, s.httpClient)

	log.Println("Getting token")
	token, err := s.oauthClient.Exchange(ctx, authCode,
		oauth2.SetAuthURLParam("code_verifier", "xalsLDydJtHwIQZukUyj6boam5vMUaJRWv-BnGCAzcZi3ZTs"),
	)

	s.token = token

	log.Println("Getting credential")
	vc, err := s.getCredential(oidcConfig.CredentialEndpoint, config.CredentialType, config.CredentialFormat)
	if err != nil {
		return fmt.Errorf("get credential: %w", err)
	}

	b, err = json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("marshal vc: %w", err)
	}

	log.Println("Adding credential to wallet")
	if err = s.wallet.Add(s.vcProviderConf.WalletParams.Token, wallet.Credential, b); err != nil {
		return fmt.Errorf("add credential to wallet: %w", err)
	}

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

func (s *Service) getAuthCodeNonInteractive(loginURL string) (string, error) {
	httpClient := &http.Client{
		Jar:       s.httpClient.Jar,
		Transport: s.httpClient.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { // hijack redirects
			return http.ErrUseLastResponse
		},
	}

	log.Println("Logging in ", loginURL)
	resp, err := httpClient.Post(loginURL, "", http.NoBody)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()

	log.Println("Redirecting to third-party oidc provider", resp.Header.Get("Location"))
	resp, err = httpClient.Get(resp.Header.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("redirect to third-party oidc provider: %w", err)
	}
	_ = resp.Body.Close()

	// redirect to consent page
	log.Println("Redirecting to consent page", resp.Header.Get("Location"))
	resp, err = httpClient.Get(resp.Header.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("redirect to consent page: %w", err)
	}
	_ = resp.Body.Close()

	// redirect back to third-party oidc provider with consent verifier
	resp, err = httpClient.Get(resp.Header.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("redirect back to auth after consent: %w", err)
	}
	_ = resp.Body.Close()

	// redirect to public vcs public /oidc/redirect
	resp, err = httpClient.Get(resp.Header.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("redirect to public oidc redirect: %w", err)
	}
	_ = resp.Body.Close()

	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("parse client redirect url: %w", err)
	}

	return u.Query().Get("code"), nil
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
