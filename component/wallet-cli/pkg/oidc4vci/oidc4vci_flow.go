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
	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/credentialoffer"
	jwssigner "github.com/trustbloc/vcs/component/wallet-cli/pkg/signer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/trustregistry"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/consent"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wellknown"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
	kmssigner "github.com/trustbloc/vcs/pkg/kms/signer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	oidc4civ1 "github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	discoverableClientIDScheme = "urn:ietf:params:oauth:client-id-scheme:oauth-discoverable-client"

	jwtProofTypeHeader      = "openid4vci-proof+jwt"
	attestJWTClientAuthType = "attest_jwt_client_auth"
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
	signer                     jose.Signer
	wellKnownService           *wellknown.Service
	trustRegistryURL           string
	flowType                   FlowType
	credentialOffer            string
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
	vc                         *verifiable.Credential
	attestationVP              string
}

type provider interface {
	HTTPClient() *http.Client
	DocumentLoader() ld.DocumentLoader
	VDRegistry() vdrapi.Registry
	CryptoSuite() api.Suite
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

	walletDID, err := did.Parse(o.walletDID)
	if err != nil {
		return nil, fmt.Errorf("parse wallet did: %w", err)
	}

	docResolution, err := p.VDRegistry().Resolve(walletDID.String())
	if err != nil {
		return nil, fmt.Errorf("resolve wallet did: %w", err)
	}

	signer, err := p.CryptoSuite().FixedKeyMultiSigner(o.walletKMSKeyID)
	if err != nil {
		return nil, fmt.Errorf("get signer for key %s: %w", o.walletKMSKeyID, err)
	}

	jwsSigner := jwssigner.NewJWSSigner(
		docResolution.DIDDocument.VerificationMethod[0].ID,
		string(o.walletSignatureType),
		kmssigner.NewKMSSigner(signer, o.walletSignatureType, nil),
	)

	return &Flow{
		httpClient:                 p.HTTPClient(),
		documentLoader:             p.DocumentLoader(),
		vdrRegistry:                p.VDRegistry(),
		signer:                     jwsSigner,
		wellKnownService:           p.WellKnownService(),
		flowType:                   o.flowType,
		credentialOffer:            o.credentialOffer,
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
		trustRegistryURL:           o.trustRegistryURL,
		attestationVP:              o.attestationVP,
	}, nil
}

func (f *Flow) GetVC() *verifiable.Credential {
	return f.vc
}

func (f *Flow) Run(ctx context.Context) error {
	slog.Info("running OIDC4VCI flow",
		"flow_type", f.flowType,
		"credential_offer_uri", f.credentialOffer,
		"credential_type", f.credentialType,
		"credential_format", f.credentialFormat,
	)

	var (
		credentialIssuer        string
		issuerState             string
		preAuthorizationGrant   *oidc4ci.PreAuthorizationGrant
		credentialOfferResponse *oidc4ci.CredentialOfferResponse
	)

	if f.flowType == FlowTypeAuthorizationCode || f.flowType == FlowTypePreAuthorizedCode {
		var err error

		credentialOfferResponse, err = f.parseCredentialOfferURI(f.credentialOffer)
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

	openIDConfig, err := f.wellKnownService.GetWellKnownOpenIDConfiguration(credentialIssuer)
	if err != nil {
		return err
	}

	if f.trustRegistryURL != "" {
		if credentialOfferResponse == nil || len(credentialOfferResponse.Credentials) == 0 {
			return fmt.Errorf("credential offer is empty")
		}

		slog.Info("validate issuer", "url", f.trustRegistryURL)

		credentialOffer := credentialOfferResponse.Credentials[0]

		var credentialType string

		for _, t := range credentialOffer.Types {
			if t != "VerifiableCredential" {
				credentialType = t
				break
			}
		}

		credentialFormat := string(credentialOffer.Format)

		if err = trustregistry.NewClient(f.httpClient, f.trustRegistryURL).
			ValidateIssuer(
				credentialOfferResponse.CredentialIssuer,
				"",
				credentialType,
				credentialFormat,
				lo.Contains(openIDConfig.TokenEndpointAuthMethodsSupported, attestJWTClientAuthType),
			); err != nil {
			return fmt.Errorf("validate issuer: %w", err)
		}
	}

	var token *oauth2.Token

	if f.flowType == FlowTypeAuthorizationCode || f.flowType == FlowTypeWalletInitiated {
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

		token, err = f.exchangeAuthorizationCodeForAccessToken(ctx, oauthClient, authCode)
		if err != nil {
			return err
		}
	} else if f.flowType == FlowTypePreAuthorizedCode {
		slog.Info("getting access token",
			"grant_type", preAuthorizedCodeGrantType,
			"client_id", f.clientID,
			"pre-authorized_code", preAuthorizationGrant.PreAuthorizedCode,
			"token_endpoint", openIDConfig.TokenEndpoint,
		)

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

		if f.attestationVP != "" {
			tokenValues.Add("client_assertion_type", attestJWTClientAuthType)
			tokenValues.Add("client_assertion", f.attestationVP)
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

	vc, err := f.getVC(token, openIDConfig, credentialIssuer)
	if err != nil {
		return err
	}

	f.vc = vc

	return nil
}

func (f *Flow) parseCredentialOfferURI(uri string) (*oidc4ci.CredentialOfferResponse, error) {
	slog.Info("parsing credential offer URI",
		"uri", uri,
	)

	parser := &credentialoffer.Parser{
		HTTPClient:  f.httpClient,
		VDRRegistry: f.vdrRegistry,
	}

	credentialOfferResponse, err := parser.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parse credential offer url: %w", err)
	}

	return credentialOfferResponse, nil
}

func (f *Flow) getAuthorizationCode(oauthClient *oauth2.Config, issuerState string) (string, error) {
	slog.Info("getting authorization code",
		"client_id", oauthClient.ClientID,
		"scopes", oauthClient.Scopes,
		"redirect_uri", oauthClient.RedirectURL,
		"authorization_endpoint", oauthClient.Endpoint.AuthURL,
	)

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
	slog.Info("exchanging authorization code for access token",
		"grant_type", "authorization_code",
		"client_id", oauthClient.ClientID,
		"auth_code", authCode,
		"token_endpoint", oauthClient.Endpoint.TokenURL,
	)

	authCodeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", "xalsLDydJtHwIQZukUyj6boam5vMUaJRWv-BnGCAzcZi3ZTs"),
	}

	// TODO: Resolve issue with unknown "client_assertion_type" parameter
	if f.attestationVP != "" {
		authCodeOptions = append(authCodeOptions,
			oauth2.SetAuthURLParam("client_assertion_type", attestJWTClientAuthType),
			oauth2.SetAuthURLParam("client_assertion", f.attestationVP),
		)
	}

	token, err := oauthClient.Exchange(ctx, authCode, authCodeOptions...)
	if err != nil {
		return nil, fmt.Errorf("exchange code for token: %w", err)
	}

	return token, nil
}

func (f *Flow) getVC(
	token *oauth2.Token,
	wellKnown *issuerv1.WellKnownOpenIDIssuerConfiguration,
	credentialIssuer string,
) (*verifiable.Credential, error) {
	credentialEndpoint := wellKnown.CredentialEndpoint
	slog.Info("getting credential",
		"credential_endpoint", credentialEndpoint,
		"credential_issuer", credentialIssuer,
	)

	claims := &JWTProofClaims{
		Issuer:   f.clientID,
		IssuedAt: time.Now().Unix(),
		Audience: credentialIssuer,
		Nonce:    token.Extra("c_nonce").(string),
	}

	headers := map[string]interface{}{
		jose.HeaderType: jwtProofTypeHeader,
	}

	signedJWT, err := jwt.NewJoseSigned(claims, headers, f.signer)
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

	if err = f.handleIssuanceAck(wellKnown, &credentialResp, token); err != nil {
		return nil, err
	}

	return parsedVC, nil
}

func (f *Flow) handleIssuanceAck(
	wellKnown *issuerv1.WellKnownOpenIDIssuerConfiguration,
	credResponse *CredentialResponse,
	token *oauth2.Token,
) error {
	if wellKnown == nil || credResponse == nil {
		return nil
	}

	if wellKnown.CredentialAckEndpoint == "" || lo.FromPtr(credResponse.AckID) == "" {
		return nil
	}

	slog.Info("Sending wallet ACK",
		"ack_id", credResponse.AckID,
		"endpoint", wellKnown.CredentialAckEndpoint,
	)

	b, err := json.Marshal(oidc4civ1.AckRequest{
		Credentials: []oidc4civ1.AcpRequestItem{
			{
				AckId:            *credResponse.AckID,
				ErrorDescription: nil,
				Status:           "success",
				IssuerIdentifier: &wellKnown.CredentialIssuer,
			},
		},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, wellKnown.CredentialAckEndpoint, bytes.NewBuffer(b))
	if err != nil {
		return fmt.Errorf("ack credential request: %w", err)
	}

	req.Header.Add("content-type", "application/json")
	req.Header.Add("authorization", "Bearer "+token.AccessToken)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("Wallet ACK sent with status code %v", resp.StatusCode))

	b, _ = io.ReadAll(resp.Body) // nolint
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("expected to receive status code %d but got status code %d with response body %s",
			http.StatusNoContent, resp.StatusCode, string(b))
	}

	return nil
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
	credentialOffer            string
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
	walletKMSKeyID             string
	walletSignatureType        vcs.SignatureType
	trustRegistryURL           string
	attestationVP              string
}

type Opt func(opts *options)

func WithFlowType(flowType FlowType) Opt {
	return func(opts *options) {
		opts.flowType = flowType
	}
}

func WithCredentialOffer(credentialOffer string) Opt {
	return func(opts *options) {
		opts.credentialOffer = credentialOffer
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

func WithWalletKMSKeyID(keyID string) Opt {
	return func(opts *options) {
		opts.walletKMSKeyID = keyID
	}
}

func WithWalletSignatureType(walletSignatureType vcs.SignatureType) Opt {
	return func(opts *options) {
		opts.walletSignatureType = walletSignatureType
	}
}

func WithTrustRegistryURL(url string) Opt {
	return func(opts *options) {
		opts.trustRegistryURL = url
	}
}

func WithAttestationVP(jwtVP string) Opt {
	return func(opts *options) {
		opts.attestationVP = jwtVP
	}
}
