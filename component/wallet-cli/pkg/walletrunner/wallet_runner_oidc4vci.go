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
	"strings"
	"time"

	"github.com/cli/browser"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/trustbloc/did-go/method/jwk"
	didkey "github.com/trustbloc/did-go/method/key"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/credentialoffer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/consent"
	"github.com/trustbloc/vcs/pkg/kms/signer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	jwtProofTypHeader = "openid4vci-proof+jwt"
)

type OIDC4VCIConfig struct {
	CredentialOfferURI         string
	ClientID                   string
	Scopes                     []string
	RedirectURI                string
	CredentialType             string
	CredentialFormat           string
	Pin                        string
	Login                      string
	Password                   string
	IssuerState                string
	EnableDiscoverableClientID bool
}

type credentialRequestOpts struct {
	signerKeyID string
	signature   string
	nonce       string
}

type OauthClientOpt func(config *oauth2.Config)

type CredentialRequestOpt func(credentialRequestOpts *credentialRequestOpts)

type Hooks struct {
	BeforeTokenRequest      []OauthClientOpt
	BeforeCredentialRequest []CredentialRequestOpt
}

func WithClientID(clientID string) OauthClientOpt {
	return func(config *oauth2.Config) {
		config.ClientID = clientID
	}
}

// WithSignerKeyID overrides signerKeyID in credentials request. For testing purpose only.
func WithSignerKeyID(keyID string) CredentialRequestOpt {
	return func(credentialRequestOpts *credentialRequestOpts) {
		credentialRequestOpts.signerKeyID = keyID
	}
}

// WithSignatureValue overrides signature in credentials request. For testing purpose only.
func WithSignatureValue(signature string) CredentialRequestOpt {
	return func(credentialRequestOpts *credentialRequestOpts) {
		credentialRequestOpts.signature = signature
	}
}

// WithNonce overrides nonce in credentials request. For testing purpose only.
func WithNonce(nonce string) CredentialRequestOpt {
	return func(credentialRequestOpts *credentialRequestOpts) {
		credentialRequestOpts.nonce = nonce
	}
}

func (s *Service) RunOIDC4VCI(config *OIDC4VCIConfig, hooks *Hooks) error {
	log.Println("Starting OIDC4VCI authorized code flow")
	log.Printf("Credential Offer URI:\n\n\t%s\n\n", config.CredentialOfferURI)

	ctx := context.Background()

	err := s.CreateWallet()
	if err != nil {
		return fmt.Errorf("create wallet: %w", err)
	}

	parser := &credentialoffer.Parser{
		HTTPClient:  s.httpClient,
		VDRRegistry: s.ariesServices.vdrRegistry,
	}

	credentialOfferResponse, err := parser.Parse(config.CredentialOfferURI)
	if err != nil {
		return fmt.Errorf("parse credential offer uri: %w", err)
	}

	s.print("Getting issuer OIDC config")

	oidcIssuerCredentialConfig, err := s.GetWellKnownOpenIDConfiguration(
		credentialOfferResponse.CredentialIssuer,
	)
	if err != nil {
		return fmt.Errorf("get OIDC credential issuer metadata: %w", err)
	}

	redirectURI, err := url.Parse(config.RedirectURI)
	if err != nil {
		return fmt.Errorf("parse redirect uri: %w", err)
	}

	var listener net.Listener

	if config.Login == "" { // bind listener for callback server to support login with a browser
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}

		redirectURI.Host = fmt.Sprintf(
			"%s:%d",
			redirectURI.Hostname(),
			listener.Addr().(*net.TCPAddr).Port,
		)
	}

	s.oauthClient = &oauth2.Config{
		ClientID:    config.ClientID,
		RedirectURL: redirectURI.String(),
		Scopes:      config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   oidcIssuerCredentialConfig.AuthorizationEndpoint,
			TokenURL:  oidcIssuerCredentialConfig.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	opState := credentialOfferResponse.Grants.AuthorizationCode.IssuerState
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

	authCodeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("issuer_state", opState),
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("authorization_details", string(b)),
	}

	if config.EnableDiscoverableClientID {
		authCodeOptions = append(authCodeOptions,
			oauth2.SetAuthURLParam("client_id_scheme", discoverableClientIDScheme))
	}

	authCodeURL := s.oauthClient.AuthCodeURL(state, authCodeOptions...)

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
	var beforeCredentialsRequestHooks []CredentialRequestOpt

	if hooks != nil {
		beforeTokenRequestHooks = hooks.BeforeTokenRequest
		beforeCredentialsRequestHooks = hooks.BeforeCredentialRequest
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

	s.print("Getting credential")

	vc, _, err := s.getCredential(
		oidcIssuerCredentialConfig.CredentialEndpoint,
		config.CredentialType,
		config.CredentialFormat,
		credentialOfferResponse.CredentialIssuer,
		beforeCredentialsRequestHooks...,
	)
	if err != nil {
		return fmt.Errorf("get credential: %w", err)
	}

	b, err = json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("marshal vc: %w", err)
	}

	s.print("Adding credential to wallet")
	if err = s.wallet.Add(b); err != nil {
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
		vcParsed.Contents().ID,
		config.CredentialType,
	)

	if !s.keepWalletOpen {
		s.wallet.Close()
	}

	return nil
}

func (s *Service) RunOIDC4CIWalletInitiated(config *OIDC4VCIConfig, hooks *Hooks) error {
	log.Println("Starting OIDC4VCI authorized code flow Wallet initiated")
	ctx := context.Background()

	issuerUrl := oidc4ci.ExtractIssuerURL(config.IssuerState)
	if issuerUrl == "" {
		return errors.New(
			"undefined scopes supplied. " +
				"Make sure one of the provided scopes is in the VCS issuer URL format")
	}

	err := s.CreateWallet()
	if err != nil {
		return fmt.Errorf("create wallet: %w", err)
	}

	oidcIssuerCredentialConfig, err := s.GetWellKnownOpenIDConfiguration(
		issuerUrl,
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
		Scopes:      config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   oidcIssuerCredentialConfig.AuthorizationEndpoint,
			TokenURL:  oidcIssuerCredentialConfig.TokenEndpoint,
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
		oauth2.SetAuthURLParam("issuer_state", issuerUrl),
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
	var beforeCredentialsRequestHooks []CredentialRequestOpt

	if hooks != nil {
		beforeTokenRequestHooks = hooks.BeforeTokenRequest
		beforeCredentialsRequestHooks = hooks.BeforeCredentialRequest
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

	s.print("Getting credential")
	vc, _, err := s.getCredential(
		oidcIssuerCredentialConfig.CredentialEndpoint,
		config.CredentialType,
		config.CredentialFormat,
		issuerUrl,
		beforeCredentialsRequestHooks...,
	)
	if err != nil {
		return fmt.Errorf("get credential: %w", err)
	}

	b, err = json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("marshal vc: %w", err)
	}

	s.print("Adding credential to wallet")
	if err = s.wallet.Add(b); err != nil {
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
		vcParsed.Contents().ID,
		config.CredentialType,
	)

	if !s.keepWalletOpen {
		s.wallet.Close()
	}

	return nil
}

func (s *Service) getAuthCode(
	config *OIDC4VCIConfig,
	authCodeURL string,
) (string, error) {
	// var loginURL, consentURL *url.URL
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
		case <-time.After(5 * time.Minute):
			return "", fmt.Errorf("timed out")
		}
	}
}

func (s *Service) getCredential(
	credentialEndpoint,
	credentialType,
	credentialFormat,
	issuerURI string,
	beforeCredentialRequestOpts ...CredentialRequestOpt,
) (interface{}, time.Duration, error) {
	credentialsRequestParamsOverride := &credentialRequestOpts{}
	for _, f := range beforeCredentialRequestOpts {
		f(credentialsRequestParamsOverride)
	}

	didKeyID := s.vcProviderConf.WalletParams.DidKeyID[0]

	fks, err := s.ariesServices.Suite().FixedKeyMultiSigner(strings.Split(didKeyID, "#")[1])
	if err != nil {
		return nil, 0, fmt.Errorf("create kms signer: %w", err)
	}

	kmsSigner := signer.NewKMSSigner(fks, s.vcProviderConf.WalletParams.SignType, nil)

	nonce := s.token.Extra("c_nonce").(string)
	if credentialsRequestParamsOverride.nonce != "" {
		nonce = credentialsRequestParamsOverride.nonce
	}

	claims := &JWTProofClaims{
		Issuer:   s.oauthClient.ClientID,
		IssuedAt: time.Now().Unix(),
		Audience: issuerURI,
		Nonce:    nonce,
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

	if credentialsRequestParamsOverride.signerKeyID != "" {
		signerKeyID = credentialsRequestParamsOverride.signerKeyID
	}

	headers := map[string]interface{}{
		jose.HeaderType: jwtProofTypHeader,
	}

	signedJWT, err := jwt.NewJoseSigned(claims, headers,
		NewJWSSigner(signerKeyID, string(s.vcProviderConf.WalletParams.SignType), kmsSigner))
	if err != nil {
		return nil, 0, fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return nil, 0, fmt.Errorf("serialize signed jwt: %w", err)
	}

	if credentialsRequestParamsOverride.signature != "" {
		chunks := strings.Split(jws, ".")
		jws = strings.Join([]string{chunks[0], chunks[1], credentialsRequestParamsOverride.signature}, ".")
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
