/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/cli/browser"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	didkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/samber/lo"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/credentialoffer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/consent"
	"github.com/trustbloc/vcs/pkg/kms/signer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	jwtProofTypHeader = "openid4vci-proof+jwt"
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

type OauthClientOpt func(config *oauth2.Config)

type Hooks struct {
	BeforeTokenRequest []OauthClientOpt
}

func WithClientID(clientID string) OauthClientOpt {
	return func(config *oauth2.Config) {
		config.ClientID = clientID
	}
}

func (s *Service) RunOIDC4CI(config *OIDC4CIConfig, hooks *Hooks) error {
	log.Println("Starting OIDC4VCI authorized code flow")
	ctx := context.Background()
	log.Printf("Initiate issuance URL:\n\n\t%s\n\n", config.InitiateIssuanceURL)
	offerResponse, err := credentialoffer.ParseInitiateIssuanceUrl(
		config.InitiateIssuanceURL,
		s.httpClient,
	)
	if err != nil {
		return fmt.Errorf("parse initiate issuance url: %w", err)
	}

	s.print("Getting issuer OIDC config")
	oidcConfig, err := s.getIssuerOIDCConfig(ctx, offerResponse.CredentialIssuer)
	if err != nil {
		return fmt.Errorf("get issuer OIDC config: %w", err)
	}

	oidcIssuerCredentialConfig, err := s.getIssuerCredentialsOIDCConfig(
		offerResponse.CredentialIssuer,
	)
	if err != nil {
		return fmt.Errorf("get issuer OIDC issuer config: %w", err)
	}

	redirectURL, err := url.Parse(config.RedirectURI)
	if err != nil {
		return fmt.Errorf("parse redirect url: %w", err)
	}

	var listener net.Listener

	if config.Login == "" { // bind listener for callback server to support log in with a browser
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}

		redirectURL.Host = fmt.Sprintf(
			"%s:%d",
			redirectURL.Hostname(),
			listener.Addr().(*net.TCPAddr).Port,
		)
	}

	s.oauthClient = &oauth2.Config{
		ClientID:    config.ClientID,
		RedirectURL: redirectURL.String(),
		Scopes:      config.Scope,
		Endpoint: oauth2.Endpoint{
			AuthURL:   oidcConfig.AuthorizationEndpoint,
			TokenURL:  oidcConfig.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	opState := offerResponse.Grants.AuthorizationCode.IssuerState
	state := uuid.New().String()

	b, err := json.Marshal(&common.AuthorizationDetails{
		Type: "openid_credential",
		Types: []string{
			"VerifiableCredential",
			config.CredentialType,
		},
		Format: lo.ToPtr(config.CredentialFormat),
	})
	if err != nil {
		return fmt.Errorf("marshal authorization details: %w", err)
	}

	authCodeURL := s.oauthClient.AuthCodeURL(state,
		oauth2.SetAuthURLParam("issuer_state", opState),
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("authorization_details", string(b)),
	)

	var authCode string

	if config.Login == "" { // interactive mode: login with a browser
		authCode, err = s.getAuthCodeFromBrowser(listener, authCodeURL)
		if err != nil {
			return fmt.Errorf("get auth code from browser: %w", err)
		}
	} else {
		authCode, err = s.getAuthCode(config, authCodeURL)
		if err != nil {
			return fmt.Errorf("get auth code: %w", err)
		}
	}

	if authCode == "" {
		return fmt.Errorf("auth code is empty")
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)

	var beforeTokenRequestHooks []OauthClientOpt

	if hooks != nil {
		beforeTokenRequestHooks = hooks.BeforeTokenRequest
	}

	for _, f := range beforeTokenRequestHooks {
		f(s.oauthClient)
	}

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
	vc, _, err := s.getCredential(
		oidcIssuerCredentialConfig.CredentialEndpoint,
		config.CredentialType,
		config.CredentialFormat,
		offerResponse.CredentialIssuer,
	)
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

	vcParsed, err := verifiable.ParseCredential(b,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(
			s.ariesServices.JSONLDDocumentLoader()))
	if err != nil {
		return fmt.Errorf("parse vc: %w", err)
	}

	log.Printf(
		"Credential with ID [%s] and type [%v] added successfully",
		vcParsed.ID,
		config.CredentialType,
	)

	if !s.keepWalletOpen {
		s.wallet.Close()
	}

	return nil
}

var matchRegex = regexp.MustCompile(oidc4ci.WalletInitFlowClaimRegex)

func extractIssuerURLFromScopes(scopes []string) (string, error) {
	for _, scope := range scopes {
		if matchRegex.MatchString(scope) {
			return scope, nil
		}
	}

	return "", errors.New("issuer URL not found in scopes")
}

func (s *Service) RunOIDC4CIWalletInitiated(config *OIDC4CIConfig, hooks *Hooks) error {
	log.Println("Starting OIDC4VCI authorized code flow Wallet initiated")
	ctx := context.Background()

	issuerUrl, err := extractIssuerURLFromScopes(config.Scope)
	if err != nil {
		return errors.New(
			"undefined scopes supplied. " +
				"Make sure one of the provided scope is in the VCS issuer URL format. ref " +
				oidc4ci.WalletInitFlowClaimRegex)
	}

	oidcIssuerCredentialConfig, err := s.getIssuerCredentialsOIDCConfig(
		issuerUrl,
	)
	if err != nil {
		return fmt.Errorf("get issuer OIDC issuer config: %w", err)
	}

	oidcConfig, err := s.getIssuerOIDCConfig(ctx, issuerUrl)
	if err != nil {
		return fmt.Errorf("get issuer OIDC config: %w", err)
	}

	redirectURL, err := url.Parse(config.RedirectURI)
	if err != nil {
		return fmt.Errorf("parse redirect url: %w", err)
	}

	var listener net.Listener

	if config.Login == "" { // bind listener for callback server to support log in with a browser
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}

		redirectURL.Host = fmt.Sprintf(
			"%s:%d",
			redirectURL.Hostname(),
			listener.Addr().(*net.TCPAddr).Port,
		)
	}

	s.oauthClient = &oauth2.Config{
		ClientID:    config.ClientID,
		RedirectURL: redirectURL.String(),
		Scopes:      config.Scope,
		Endpoint: oauth2.Endpoint{
			AuthURL:   oidcConfig.AuthorizationEndpoint,
			TokenURL:  oidcConfig.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	state := uuid.New().String()

	b, err := json.Marshal(&common.AuthorizationDetails{
		Type: "openid_credential",
		Types: []string{
			"VerifiableCredential",
			config.CredentialType,
		},
		Format: lo.ToPtr(config.CredentialFormat),
	})
	if err != nil {
		return fmt.Errorf("marshal authorization details: %w", err)
	}

	authCodeURL := s.oauthClient.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("authorization_details", string(b)),
	)

	var authCode string

	if config.Login == "" { // interactive mode: login with a browser
		authCode, err = s.getAuthCodeFromBrowser(listener, authCodeURL)
		if err != nil {
			return fmt.Errorf("get auth code from browser: %w", err)
		}
	} else {
		authCode, err = s.getAuthCode(config, authCodeURL)
		if err != nil {
			return fmt.Errorf("get auth code: %w", err)
		}
	}

	if authCode == "" {
		return fmt.Errorf("auth code is empty")
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)

	var beforeTokenRequestHooks []OauthClientOpt

	if hooks != nil {
		beforeTokenRequestHooks = hooks.BeforeTokenRequest
	}

	for _, f := range beforeTokenRequestHooks {
		f(s.oauthClient)
	}

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
	vc, _, err := s.getCredential(
		oidcIssuerCredentialConfig.CredentialEndpoint,
		config.CredentialType,
		config.CredentialFormat,
		issuerUrl,
	)
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

	vcParsed, err := verifiable.ParseCredential(b,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(
			s.ariesServices.JSONLDDocumentLoader()))
	if err != nil {
		return fmt.Errorf("parse VC: %w", err)
	}

	log.Printf(
		"Credential with ID [%s] and type [%v] added successfully",
		vcParsed.ID,
		config.CredentialType,
	)

	if !s.keepWalletOpen {
		s.wallet.Close()
	}

	return nil
}

func (s *Service) getIssuerOIDCConfig(
	ctx context.Context,
	issuerURL string,
) (*issuerv1.WellKnownOpenIDConfiguration, error) {
	// GET /issuer/{profileID}/{profileVersion}/.well-known/openid-configuration
	req, err := http.NewRequestWithContext(ctx, "GET", issuerURL+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
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

func (s *Service) getIssuerCredentialsOIDCConfig(
	issuerURL string,
) (*issuerv1.WellKnownOpenIDIssuerConfiguration, error) {
	// GET /issuer/{profileID}/.well-known/openid-credential-issuer
	resp, err := s.httpClient.Get(issuerURL + "/.well-known/openid-credential-issuer")
	if err != nil {
		return nil, fmt.Errorf("get issuer well-known: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get issuer well-known: status code %d", resp.StatusCode)
	}

	var oidcConfig issuerv1.WellKnownOpenIDIssuerConfiguration

	if err = json.NewDecoder(resp.Body).Decode(&oidcConfig); err != nil {
		return nil, fmt.Errorf("decode issuer well-known: %w", err)
	}

	return &oidcConfig, nil
}

func (s *Service) getAuthCode(
	config *OIDC4CIConfig,
	authCodeURL string,
) (string, error) {
	//var loginURL, consentURL *url.URL
	var authCode string

	httpClient := &http.Client{
		Jar:       s.httpClient.Jar,
		Transport: s.httpClient.Transport,
	}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), ".amazoncognito.com/login") {
			s.print("got cognito consent screen")
			return consent.NewCognito(
				httpClient,
				httpClient.Jar.Cookies(req.URL),
				req.URL.String(),
				config.Login, config.Password,
			).Execute()
		}

		// intercept client auth code
		if strings.HasPrefix(req.URL.String(), config.RedirectURI) {
			authCode = req.URL.Query().Get("code")

			return http.ErrUseLastResponse
		}

		return nil
	}

	s.print("Getting authorization code")
	resp, err := httpClient.Get(authCodeURL)
	if err != nil {
		return "", fmt.Errorf("get auth code: %w", err)
	}
	_ = resp.Body.Close()

	return authCode, nil
}

func (s *Service) getAuthCodeFromBrowser(
	listener net.Listener,
	authCodeURL string,
) (string, error) {
	server := &callbackServer{
		listener: listener,
		codeChan: make(chan string, 1),
	}

	go func() {
		http.Serve(listener, server)
	}()

	log.Printf(
		"Log in with a browser:\n\n%s\n\nor press [Enter] to open link in your default browser\n",
		authCodeURL,
	)

	done := make(chan struct{})

	go waitForEnter(done)

	for {
		select {
		case <-done:
			if err := browser.OpenURL(authCodeURL); err != nil {
				return "", fmt.Errorf("open browser: %w", err)
			}
		case authCode := <-server.codeChan:
			log.Printf("Received authorization code: %s", authCode)
			return authCode, nil
		case <-time.After(3 * time.Minute):
			return "", fmt.Errorf("timed out")
		}
	}
}

func (s *Service) getCredential(
	credentialEndpoint,
	credentialType,
	credentialFormat,
	issuerURI string,
) (interface{}, time.Duration, error) {
	km := s.ariesServices.KMS()
	cr := s.ariesServices.Crypto()

	didKeyID := s.vcProviderConf.WalletParams.DidKeyID[0]

	kmsSigner, err := signer.NewKMSSigner(
		km,
		cr,
		strings.Split(didKeyID, "#")[1],
		s.vcProviderConf.WalletParams.SignType,
		nil,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("create kms signer: %w", err)
	}

	claims := &JWTProofClaims{
		Issuer:   s.oauthClient.ClientID,
		IssuedAt: time.Now().Unix(),
		Audience: issuerURI,
		Nonce:    s.token.Extra("c_nonce").(string),
	}

	signerKeyID := didKeyID

	if strings.Contains(didKeyID, "did:key") {
		res, err := didkey.New().Read(strings.Split(didKeyID, "#")[0])
		if err != nil {
			return nil, 0, err
		}

		signerKeyID = res.DIDDocument.VerificationMethod[0].ID
	} else if strings.Contains(didKeyID, "did:jwk") {
		res, err := jwk.New().Read(strings.Split(didKeyID, "#")[0])
		if err != nil {
			return "", 0, err
		}

		signerKeyID = res.DIDDocument.VerificationMethod[0].ID
	}

	signedJWT, err := jwt.NewSigned(claims, nil,
		NewJWSSigner(signerKeyID, string(s.vcProviderConf.WalletParams.SignType), kmsSigner))
	if err != nil {
		return nil, 0, fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return nil, 0, fmt.Errorf("serialize signed jwt: %w", err)
	}

	b, err := json.Marshal(CredentialRequest{
		Format: credentialFormat,
		Types:  []string{"VerifiableCredential", credentialType},
		Proof: JWTProof{
			ProofType: "jwt",
			JWT:       jws,
		},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("marshal credential request: %w", err)
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, s.httpClient)

	httpClient := s.oauthClient.Client(ctx, s.token)

	vcsStart := time.Now()
	finalDuration := time.Duration(0)
	resp, err := httpClient.Post(credentialEndpoint, "application/json", bytes.NewBuffer(b))
	finalDuration = time.Since(vcsStart)
	if err != nil {
		return nil, 0, fmt.Errorf("get credential: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, finalDuration, fmt.Errorf(
			"get credential: status %s and body %s",
			resp.Status,
			string(b),
		)
	}

	var credentialResp CredentialResponse

	if err = json.NewDecoder(resp.Body).Decode(&credentialResp); err != nil {
		return nil, finalDuration, fmt.Errorf("decode credential response: %w", err)
	}

	return credentialResp.Credential, finalDuration, nil
}

func (s *Service) print(
	msg string,
) {
	if s.debug {
		fmt.Println()
	}

	log.Printf("%s\n\n", msg)
}

func waitForEnter(
	done chan<- struct{},
) {
	_, _ = fmt.Scanln()
	done <- struct{}{}
}

type callbackServer struct {
	listener net.Listener
	codeChan chan string
}

func (s *callbackServer) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.URL.Path != "/callback" {
		http.NotFound(w, r)

		return
	}

	defer func() {
		_ = s.listener.Close()
	}()

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code is empty", http.StatusBadRequest)

		return
	}

	s.codeChan <- code

	w.Header().Add("content-type", "text/html")
	_, _ = fmt.Fprintf(w, "<p>Authorization code received! You may now close this page.</p>")
}
