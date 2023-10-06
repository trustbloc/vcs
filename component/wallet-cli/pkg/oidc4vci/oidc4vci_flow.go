/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vci

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cli/browser"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/spi/crypto"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/credentialoffer"
	jwssigner "github.com/trustbloc/vcs/component/wallet-cli/pkg/signer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/consent"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wellknown"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
	kmssigner "github.com/trustbloc/vcs/pkg/kms/signer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	oidc4civ1 "github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	discoverableClientIDScheme = "urn:ietf:params:oauth:client-id-scheme:oauth-discoverable-client"

	jwtProofTypeHeader = "openid4vci-proof+jwt"
)

type FlowType string

const (
	FlowTypeAuthorizationCode FlowType = "authorization_code"
	FlowTypeWalletInitiated            = "wallet_initiated"
	FlowTypePreAuthorizedCode          = "pre-authorized_code"
)

type Flow struct {
	httpClient                 *http.Client
	documentLoader             ld.DocumentLoader
	vdrRegistry                vdrapi.Registry
	keyManager                 kms.KeyManager
	crypto                     crypto.Crypto
	wellknownService           *wellknown.Service
	flowType                   FlowType
	credentialOfferURI         string
	credentialType             string
	credentialFormat           string
	clientID                   string
	scopes                     []string
	redirectURI                string
	enableDiscoverableClientID bool
	userLogin                  string
	userPassword               string
	issuerState                string
	pin                        string
	walletDID                  string
	walletSignatureType        vcs.SignatureType
	vc                         *verifiable.Credential
}

type provider interface {
	HTTPClient() *http.Client
	DocumentLoader() ld.DocumentLoader
	VDRegistry() vdrapi.Registry
	KMS() kms.KeyManager
	Crypto() crypto.Crypto
	WellKnownService() *wellknown.Service
}

func NewFlow(p provider, opts ...Opt) (*Flow, error) {
	o := &options{
		flowType: FlowTypeAuthorizationCode,
	}

	for i := range opts {
		opts[i](o)
	}

	switch o.flowType {
	case FlowTypeAuthorizationCode:
		if o.clientID == "" {
			return nil, fmt.Errorf("client id not set")
		}

		if o.redirectURI == "" {
			return nil, fmt.Errorf("redirect uri not set")
		}

		if _, err := url.Parse(o.redirectURI); err != nil {
			return nil, fmt.Errorf("invalid redirect uri: %w", err)
		}

		if len(o.scopes) == 0 {
			return nil, fmt.Errorf("scopes not set")
		}
	case FlowTypePreAuthorizedCode:
		break
	case FlowTypeWalletInitiated:
		if o.issuerState == "" {
			return nil, fmt.Errorf("issuer state not set")
		}
	default:
		return nil, fmt.Errorf("unsupported flow type: %d", o.flowType)
	}

	return &Flow{
		httpClient:                 p.HTTPClient(),
		documentLoader:             p.DocumentLoader(),
		vdrRegistry:                p.VDRegistry(),
		keyManager:                 p.KMS(),
		crypto:                     p.Crypto(),
		wellknownService:           p.WellKnownService(),
		flowType:                   o.flowType,
		credentialOfferURI:         o.credentialOfferURI,
		credentialType:             o.credentialType,
		credentialFormat:           o.credentialFormat,
		clientID:                   o.clientID,
		scopes:                     o.scopes,
		redirectURI:                o.redirectURI,
		enableDiscoverableClientID: o.enableDiscoverableClientID,
		userLogin:                  o.userLogin,
		userPassword:               o.userPassword,
		issuerState:                o.issuerState,
		pin:                        o.pin,
		walletDID:                  o.walletDID,
		walletSignatureType:        o.walletSignatureType,
	}, nil
}

func (f *Flow) GetVC() *verifiable.Credential {
	return f.vc
}

func (f *Flow) Run(ctx context.Context) error {
	slog.Info("running OIDC4VCI flow",
		"flow_type", f.flowType,
		"credential_offer_uri", f.credentialOfferURI,
		"credential_type", f.credentialType,
		"credential_format", f.credentialFormat,
	)

	var (
		credentialIssuer      string
		issuerState           string
		preAuthorizationGrant *oidc4ci.PreAuthorizationGrant
	)

	if f.flowType == FlowTypeAuthorizationCode || f.flowType == FlowTypePreAuthorizedCode {
		// 1. Parse credential offer URI
		credentialOfferResponse, err := f.parseCredentialOfferURI(f.credentialOfferURI)
		if err != nil {
			return err
		}

		credentialIssuer = credentialOfferResponse.CredentialIssuer

		if credentialOfferResponse.Grants.AuthorizationCode != nil {
			issuerState = credentialOfferResponse.Grants.AuthorizationCode.IssuerState
		}

		if credentialOfferResponse.Grants.PreAuthorizationGrant != nil {
			preAuthorizationGrant = credentialOfferResponse.Grants.PreAuthorizationGrant
		}
	} else if f.flowType == FlowTypeWalletInitiated {
		credentialIssuer = f.issuerState
		issuerState = f.issuerState
	}

	// 2. Get issuer OpenID configuration
	openIDConfig, err := f.wellknownService.GetWellKnownOpenIDConfiguration(credentialIssuer)
	if err != nil {
		return err
	}

	var token *oauth2.Token

	if f.flowType == FlowTypeAuthorizationCode {
		// 3.1. Get authorization code
		oauthClient := &oauth2.Config{
			ClientID: f.clientID,
			Scopes:   f.scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:   openIDConfig.AuthorizationEndpoint,
				TokenURL:  openIDConfig.TokenEndpoint,
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		}

		var authCode string

		authCode, err = f.getAuthorizationCode(oauthClient, issuerState)
		if err != nil {
			return err
		}

		// 3.2. Exchange authorization code for access token
		token, err = f.exchangeAuthorizationCodeForAccessToken(ctx, oauthClient, authCode)
		if err != nil {
			return err
		}
	} else if f.flowType == FlowTypePreAuthorizedCode {
		// 3. Get access token
		tokenValues := url.Values{
			"grant_type":          []string{preAuthorizedCodeGrantType},
			"pre-authorized_code": []string{preAuthorizationGrant.PreAuthorizedCode},
			"client_id":           []string{f.clientID},
		}

		if preAuthorizationGrant.UserPinRequired {
			if f.pin == "" {
				fmt.Printf("\nEnter PIN:\n")
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan()
				f.pin = scanner.Text()
			}

			tokenValues.Add("user_pin", f.pin)
		}

		var resp *http.Response

		if resp, err = f.httpClient.PostForm(openIDConfig.TokenEndpoint, tokenValues); err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			b, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return readErr
			}

			return fmt.Errorf(
				"get access token: status %s and body %s",
				resp.Status,
				string(b),
			)
		}

		var tokenResp oidc4civ1.AccessTokenResponse

		if err = json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return err
		}
		_ = resp.Body.Close()

		token = &oauth2.Token{
			AccessToken: tokenResp.AccessToken,
			TokenType:   tokenResp.TokenType,
			Expiry:      time.Now().Add(time.Duration(lo.FromPtr(tokenResp.ExpiresIn)) * time.Second),
		}

		token = token.WithExtra(
			map[string]interface{}{
				"c_nonce": *tokenResp.CNonce,
			},
		)
	}

	// 5. Get VC
	vc, err := f.getVC(token, openIDConfig.CredentialEndpoint, credentialIssuer)
	if err != nil {
		return err
	}

	f.vc = vc

	return nil
}

func (f *Flow) parseCredentialOfferURI(uri string) (*oidc4ci.CredentialOfferResponse, error) {
	parser := &credentialoffer.Parser{
		HTTPClient:  f.httpClient,
		VDRRegistry: f.vdrRegistry,
	}

	credentialOfferResponse, err := parser.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parse credential offer uri: %w", err)
	}

	slog.Debug("parsed credential offer",
		"credential_issuer", credentialOfferResponse.CredentialIssuer,
		"grants", credentialOfferResponse.Grants,
	)

	return credentialOfferResponse, nil
}

func (f *Flow) getAuthorizationCode(oauthClient *oauth2.Config, issuerState string) (string, error) {
	var (
		listener net.Listener
		err      error
	)

	redirectURI, err := url.Parse(f.redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect uri: %w", err)
	}

	if f.userLogin == "" { // interactive mode: user enters login and password manually
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return "", fmt.Errorf("listen: %w", err)
		}

		redirectURI.Host = fmt.Sprintf(
			"%s:%d",
			redirectURI.Hostname(),
			listener.Addr().(*net.TCPAddr).Port,
		)
	}

	oauthClient.RedirectURL = redirectURI.String()

	b, err := json.Marshal(&common.AuthorizationDetails{
		Type: "openid_credential",
		Types: []string{
			"VerifiableCredential",
			f.credentialType,
		},
		Format: lo.ToPtr(f.credentialFormat),
	})
	if err != nil {
		return "", fmt.Errorf("marshal authorization details: %w", err)
	}

	authCodeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("issuer_state", issuerState),
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("authorization_details", string(b)),
	}

	if f.enableDiscoverableClientID {
		authCodeOptions = append(authCodeOptions,
			oauth2.SetAuthURLParam("client_id_scheme", discoverableClientIDScheme))
	}

	state := uuid.New().String()

	authCodeURL := oauthClient.AuthCodeURL(state, authCodeOptions...)

	var authCode string

	if f.userLogin == "" { // interactive mode: login with a browser
		authCode, err = f.interceptAuthCodeFromBrowser(authCodeURL, listener)
		if err != nil {
			return "", fmt.Errorf("get auth code from browser: %w", err)
		}
	} else {
		authCode, err = f.interceptAuthCode(authCodeURL)
		if err != nil {
			return "", fmt.Errorf("get auth code: %w", err)
		}
	}

	return authCode, nil
}

func (f *Flow) interceptAuthCode(authCodeURL string) (string, error) {
	var authCode string

	httpClient := &http.Client{
		Jar:       f.httpClient.Jar,
		Transport: f.httpClient.Transport,
	}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), ".amazoncognito.com/login") {
			slog.Debug("got cognito consent screen")
			return consent.NewCognito(
				httpClient,
				httpClient.Jar.Cookies(req.URL),
				req.URL.String(),
				f.userLogin,
				f.userPassword,
			).Execute()
		}

		// intercept client auth code
		if strings.HasPrefix(req.URL.String(), f.redirectURI) {
			authCode = req.URL.Query().Get("code")

			return http.ErrUseLastResponse
		}

		return nil
	}

	resp, err := httpClient.Get(authCodeURL)
	if err != nil {
		return "", fmt.Errorf("get auth code: %w", err)
	}
	_ = resp.Body.Close()

	slog.Debug("received auth code",
		"code", authCode,
	)

	return authCode, nil
}

func (f *Flow) interceptAuthCodeFromBrowser(
	authCodeURL string,
	listener net.Listener,
) (string, error) {
	server := &callbackServer{
		listener: listener,
		codeChan: make(chan string, 1),
	}

	go func() {
		_ = http.Serve(listener, server)
	}()

	fmt.Printf(
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
			slog.Debug("received authorization code",
				"code", authCode,
			)
			return authCode, nil
		case <-time.After(5 * time.Minute):
			return "", fmt.Errorf("timed out")
		}
	}
}

func (f *Flow) exchangeAuthorizationCodeForAccessToken(
	ctx context.Context,
	oauthClient *oauth2.Config,
	authCode string,
) (*oauth2.Token, error) {
	token, err := oauthClient.Exchange(ctx, authCode,
		oauth2.SetAuthURLParam("code_verifier", "xalsLDydJtHwIQZukUyj6boam5vMUaJRWv-BnGCAzcZi3ZTs"),
	)
	if err != nil {
		return nil, fmt.Errorf("exchange code for token: %w", err)
	}

	return token, nil
}

func (f *Flow) getVC(
	token *oauth2.Token,
	credentialEndpoint,
	credentialIssuer string,
) (*verifiable.Credential, error) {
	docResolution, err := f.vdrRegistry.Resolve(f.walletDID)
	if err != nil {
		return nil, err
	}

	signerKeyID := docResolution.DIDDocument.VerificationMethod[0].ID
	kmsKeyID := strings.Split(signerKeyID, "#")[1]

	kmsSigner, err := kmssigner.NewKMSSigner(
		f.keyManager,
		f.crypto,
		kmsKeyID,
		f.walletSignatureType,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create kms signer: %w", err)
	}

	claims := &JWTProofClaims{
		Issuer:   f.clientID,
		IssuedAt: time.Now().Unix(),
		Audience: credentialIssuer,
		Nonce:    token.Extra("c_nonce").(string),
	}

	headers := map[string]interface{}{
		jose.HeaderType: jwtProofTypeHeader,
	}

	signedJWT, err := jwt.NewSigned(
		claims,
		headers,
		jwssigner.NewJWSSigner(signerKeyID, string(f.walletSignatureType), kmsSigner),
	)
	if err != nil {
		return nil, fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return nil, fmt.Errorf("serialize signed jwt: %w", err)
	}

	b, err := json.Marshal(CredentialRequest{
		Format: f.credentialFormat,
		Types:  []string{"VerifiableCredential", f.credentialType},
		Proof: JWTProof{
			ProofType: "jwt",
			JWT:       jws,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal credential request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, credentialEndpoint, bytes.NewBuffer(b))
	if err != nil {
		return nil, fmt.Errorf("new credential request: %w", err)
	}

	req.Header.Add("content-type", "application/json")
	req.Header.Add("authorization", "Bearer "+token.AccessToken)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post to credential endpoint: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Error("failed to close response body", "err", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		if b, err = io.ReadAll(resp.Body); err != nil {
			return nil, err
		}

		return nil, fmt.Errorf(
			"get credential: status %s and body %s",
			resp.Status,
			string(b),
		)
	}

	var credentialResp CredentialResponse

	if err = json.NewDecoder(resp.Body).Decode(&credentialResp); err != nil {
		return nil, fmt.Errorf("decode credential response: %w", err)
	}

	vcBytes, err := json.Marshal(credentialResp.Credential)
	if err != nil {
		return nil, fmt.Errorf("marshal credential response: %w", err)
	}

	parsedVC, err := verifiable.ParseCredential(vcBytes,
		verifiable.WithJSONLDDocumentLoader(f.documentLoader),
		verifiable.WithDisabledProofCheck(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse credential: %w", err)
	}

	return parsedVC, nil
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

type options struct {
	flowType                   FlowType
	credentialOfferURI         string
	credentialType             string
	credentialFormat           string
	clientID                   string
	scopes                     []string
	redirectURI                string
	enableDiscoverableClientID bool
	userLogin                  string
	userPassword               string
	issuerState                string
	pin                        string
	walletDID                  string
	walletSignatureType        vcs.SignatureType
}

type Opt func(opts *options)

func WithFlowType(flowType FlowType) Opt {
	return func(opts *options) {
		opts.flowType = flowType
	}
}

func WithCredentialOfferURI(credentialOfferURI string) Opt {
	return func(opts *options) {
		opts.credentialOfferURI = credentialOfferURI
	}
}

func WithCredentialType(credentialType string) Opt {
	return func(opts *options) {
		opts.credentialType = credentialType
	}
}

func WithCredentialFormat(credentialFormat string) Opt {
	return func(opts *options) {
		opts.credentialFormat = credentialFormat
	}
}

func WithClientID(clientID string) Opt {
	return func(opts *options) {
		opts.clientID = clientID
	}
}

func WithScopes(scopes []string) Opt {
	return func(opts *options) {
		opts.scopes = scopes
	}
}

func WithRedirectURI(redirectURI string) Opt {
	return func(opts *options) {
		opts.redirectURI = redirectURI
	}
}

func WithEnableDiscoverableClientID() Opt {
	return func(opts *options) {
		opts.enableDiscoverableClientID = true
	}
}

func WithUserLogin(userLogin string) Opt {
	return func(opts *options) {
		opts.userLogin = userLogin
	}
}

func WithUserPassword(userPassword string) Opt {
	return func(opts *options) {
		opts.userPassword = userPassword
	}
}

func WithIssuerState(issuerState string) Opt {
	return func(opts *options) {
		opts.issuerState = issuerState
	}
}

func WithPin(pin string) Opt {
	return func(opts *options) {
		opts.pin = pin
	}
}

func WithWalletDID(walletDID string) Opt {
	return func(opts *options) {
		opts.walletDID = walletDID
	}
}

func WithWalletSignatureType(walletSignatureType vcs.SignatureType) Opt {
	return func(opts *options) {
		opts.walletSignatureType = walletSignatureType
	}
}
