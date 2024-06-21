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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/cli/browser"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/consent"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/credentialoffer"
	jwssigner "github.com/trustbloc/vcs/component/wallet-cli/pkg/signer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/trustregistry"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wellknown"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
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

type AttestationService interface {
	GetAttestation(ctx context.Context, request attestation.GetAttestationRequest) (string, error)
}

type TrustRegistry interface {
	ValidateIssuer(
		ctx context.Context,
		issuerDID string,
		issuerDomain string,
		credentialOffers []trustregistry.CredentialOffer,
	) (bool, error)
}

type Flow struct {
	httpClient         *http.Client
	documentLoader     ld.DocumentLoader
	vdrRegistry        vdrapi.Registry
	signer             jose.Signer
	proofBuilder       ProofBuilder
	wallet             *wallet.Wallet
	wellKnownService   *wellknown.Service
	attestationService AttestationService
	trustRegistry      TrustRegistry
	flowType           FlowType
	credentialOffer    string
	credentialFilters  []*credentialFilter
	// credentialConfigurationIDs is used to define common.AuthorizationDetails .CredentialConfigurationId in authorization request.
	// Also, according to deprecated API, is used to define vcsverifiable.OIDCFormat in credential request.
	credentialConfigurationIDs  []string
	clientID                    string
	scopes                      []string
	redirectURI                 string
	enableDiscoverableClientID  bool
	useBatchCredentialsEndpoint bool
	userLogin                   string
	userPassword                string
	issuerState                 string
	pin                         string
	walletKeyID                 string
	walletKeyType               kms.KeyType
	perfInfo                    *PerfInfo
}

type credentialFilter struct {
	// stores credential type being issued with exclusion of "VerifiableCredential".
	// Examples: "CrudeProductCredential", "PermanentResidentCard"
	// Spec: https://www.w3.org/TR/vc-data-model/#types
	credentialType string
	// stores vcsverifiable.OIDCFormat of credential being issued.
	oidcCredentialFormat vcsverifiable.OIDCFormat
}

type provider interface {
	HTTPClient() *http.Client
	DocumentLoader() ld.DocumentLoader
	VDRegistry() vdrapi.Registry
	CryptoSuite() api.Suite
	AttestationService() AttestationService
	TrustRegistry() TrustRegistry
	Wallet() *wallet.Wallet
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
		return nil, fmt.Errorf("unsupported flow type: %s", o.flowType)
	}

	if o.walletDIDIndex < 0 || o.walletDIDIndex >= len(p.Wallet().DIDs()) {
		return nil, fmt.Errorf("invalid wallet did index: %d", o.walletDIDIndex)
	}

	walletDIDInfo := p.Wallet().DIDs()[o.walletDIDIndex]

	walletDID, err := did.Parse(walletDIDInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("parse wallet did: %w", err)
	}

	docResolution, err := p.VDRegistry().Resolve(walletDID.String())
	if err != nil {
		return nil, fmt.Errorf("resolve wallet did: %w", err)
	}

	signer, err := p.CryptoSuite().FixedKeyMultiSigner(walletDIDInfo.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get signer for key %s: %w", walletDIDInfo.KeyID, err)
	}

	signatureType := p.Wallet().SignatureType()

	jwsSigner := jwssigner.NewJWSSigner(
		docResolution.DIDDocument.VerificationMethod[0].ID,
		string(signatureType),
		kmssigner.NewKMSSigner(signer, signatureType, nil),
	)

	proofBuilder := o.proofBuilder

	if proofBuilder == nil {
		proofBuilder = NewJWTProofBuilder()
	}

	return &Flow{
		httpClient:                  p.HTTPClient(),
		documentLoader:              p.DocumentLoader(),
		vdrRegistry:                 p.VDRegistry(),
		signer:                      jwsSigner,
		proofBuilder:                proofBuilder,
		wallet:                      p.Wallet(),
		wellKnownService:            p.WellKnownService(),
		attestationService:          p.AttestationService(),
		trustRegistry:               p.TrustRegistry(),
		walletKeyID:                 walletDIDInfo.KeyID,
		walletKeyType:               walletDIDInfo.KeyType,
		flowType:                    o.flowType,
		credentialOffer:             o.credentialOffer,
		clientID:                    o.clientID,
		credentialConfigurationIDs:  o.credentialConfigurationIDs,
		credentialFilters:           o.credentialFilters,
		scopes:                      o.scopes,
		redirectURI:                 o.redirectURI,
		enableDiscoverableClientID:  o.enableDiscoverableClientID,
		useBatchCredentialsEndpoint: o.useBatchCredentialsEndpoint,
		userLogin:                   o.userLogin,
		userPassword:                o.userPassword,
		issuerState:                 o.issuerState,
		pin:                         o.pin,
		perfInfo:                    &PerfInfo{},
	}, nil
}

func (f *Flow) Run(ctx context.Context) ([]*verifiable.Credential, error) {
	totalFlowStart := time.Now()
	defer func() {
		f.perfInfo.VcsCIFlowDuration = time.Since(totalFlowStart)
	}()

	slog.Info("Running OIDC4VCI flow",
		"flow_type", f.flowType,
		"credential_offer_uri", f.credentialOffer,
		"credential_filters", f.credentialFilters,
		"scope", f.scopes,
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
			return nil, err
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

	start := time.Now()

	openIDConfig, err := f.wellKnownService.GetWellKnownOpenIDConfiguration(credentialIssuer)
	if err != nil {
		return nil, err
	}

	f.perfInfo.GetIssuerCredentialsOIDCConfig = time.Since(start)

	var token *oauth2.Token

	start = time.Now()

	if f.flowType == FlowTypeAuthorizationCode || f.flowType == FlowTypeWalletInitiated {
		oauthClient := &oauth2.Config{
			ClientID: f.clientID,
			Scopes:   f.scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:   lo.FromPtr(openIDConfig.AuthorizationEndpoint),
				TokenURL:  lo.FromPtr(openIDConfig.TokenEndpoint),
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		}

		var authCode string

		authCode, err = f.getAuthorizationCode(oauthClient, issuerState)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, oauth2.HTTPClient, f.httpClient)

		token, err = f.exchangeAuthorizationCodeForAccessToken(ctx, oauthClient, authCode)
		if err != nil {
			return nil, err
		}
	} else if f.flowType == FlowTypePreAuthorizedCode {
		slog.Info("Getting access token",
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

		if preAuthorizationGrant.TxCode != nil {
			if f.pin == "" {
				fmt.Printf("\nEnter PIN:\n")
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan()
				f.pin = scanner.Text()
			}

			tokenValues.Add("tx_code", f.pin)
		}

		issuerDID := f.wellKnownService.GetIssuerDID()

		if issuerDID == "" {
			slog.Warn("Issuer DID is empty. Does '/.well-known/openid-credential-issuer' return jwt?")
		}

		if len(credentialOfferResponse.CredentialConfigurationIDs) == 0 {
			return nil, fmt.Errorf("no credential configuration id defined in credential offer")
		}

		var attestationRequired bool

		if f.trustRegistry != nil && !reflect.ValueOf(f.trustRegistry).IsNil() {
			var credentialOffers []trustregistry.CredentialOffer

			clientAttestationRequested := lo.Contains(
				lo.FromPtr(openIDConfig.TokenEndpointAuthMethodsSupported),
				attestJWTClientAuthType,
			)

			for _, configurationID := range credentialOfferResponse.CredentialConfigurationIDs {
				credentialConfiguration := openIDConfig.CredentialConfigurationsSupported.AdditionalProperties[configurationID]

				var credentialType string

				for _, t := range credentialConfiguration.CredentialDefinition.Type {
					if t != "VerifiableCredential" {
						credentialType = t
						break
					}
				}

				credentialOffers = append(credentialOffers,
					trustregistry.CredentialOffer{
						ClientAttestationRequested: clientAttestationRequested,
						CredentialFormat:           credentialConfiguration.Format,
						CredentialType:             credentialType,
					},
				)
			}

			attestationRequired, err = f.trustRegistry.ValidateIssuer(ctx, issuerDID, "", credentialOffers)
			if err != nil {
				return nil, fmt.Errorf("validate issuer: %w", err)
			}
		}

		if attestationRequired {
			var jwtVP string

			jwtVP, err = f.attestationService.GetAttestation(ctx, attestation.GetAttestationRequest{
				Audience: issuerDID,
				Nonce:    preAuthorizationGrant.PreAuthorizedCode,
			})
			if err != nil {
				return nil, fmt.Errorf("get attestation: %w", err)
			}

			tokenValues.Add("client_assertion_type", attestJWTClientAuthType)
			tokenValues.Add("client_assertion", jwtVP)
		}

		var resp *http.Response

		if resp, err = f.httpClient.PostForm(lo.FromPtr(openIDConfig.TokenEndpoint), tokenValues); err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			b, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return nil, readErr
			}

			return nil, fmt.Errorf(
				"get access token: status %s and body %s",
				resp.Status,
				string(b),
			)
		}

		var tokenResp oidc4civ1.AccessTokenResponse

		if err = json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return nil, err
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

	f.perfInfo.GetAccessToken = time.Since(start)

	return f.receiveVC(token, openIDConfig, credentialOfferResponse, credentialIssuer)
}

func (f *Flow) Signer() jose.Signer {
	return f.signer
}

func (f *Flow) parseCredentialOfferURI(uri string) (*oidc4ci.CredentialOfferResponse, error) {
	slog.Info("Parsing credential offer URI",
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

func (f *Flow) getAuthorizationCode(
	oauthClient *oauth2.Config,
	issuerState string,
) (string, error) {
	slog.Info("Getting authorization code",
		"client_id", oauthClient.ClientID,
		"scopes", oauthClient.Scopes,
		"filters", f.credentialFilters,
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

	authCodeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("issuer_state", issuerState),
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}

	authorizationDetailsRequestBody, err := f.getAuthorizationDetailsRequestBody()
	if err != nil {
		return "", fmt.Errorf("getAuthorizationDetailsRequestBody: %w", err)
	}

	// If neither credential_configuration_id nor format params supplied authorizationDetailsRequestBody will be empty.
	// In this case Wallet CLI should use scope parameter to request credential type:
	// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.2
	if len(authorizationDetailsRequestBody) > 0 {
		authCodeOptions = append(authCodeOptions,
			oauth2.SetAuthURLParam("authorization_details", string(authorizationDetailsRequestBody)))
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
	slog.Info("Exchanging authorization code for access token",
		"grant_type", "authorization_code",
		"client_id", oauthClient.ClientID,
		"auth_code", authCode,
		"token_endpoint", oauthClient.Endpoint.TokenURL,
	)

	authCodeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", "xalsLDydJtHwIQZukUyj6boam5vMUaJRWv-BnGCAzcZi3ZTs"),
	}

	// TODO: Implement client attestation support for authorization code flow

	token, err := oauthClient.Exchange(ctx, authCode, authCodeOptions...)
	if err != nil {
		return nil, fmt.Errorf("exchange code for token: %w", err)
	}

	return token, nil
}

func (f *Flow) getAttestationVP() (string, error) {
	pd := &presexch.PresentationDefinition{
		ID: uuid.New().String(),
		InputDescriptors: []*presexch.InputDescriptor{
			{
				ID:      uuid.New().String(),
				Name:    "type",
				Purpose: "wallet attestation vc requested",
				Constraints: &presexch.Constraints{
					Fields: []*presexch.Field{
						{
							ID:   uuid.New().String(),
							Path: []string{"$.type"},
							Filter: &presexch.Filter{
								Type: lo.ToPtr("array"),
								Contains: map[string]interface{}{
									"pattern": "WalletAttestationCredential",
								},
							},
						},
					},
				},
			},
		},
	}

	b, err := json.Marshal(pd)
	if err != nil {
		return "", fmt.Errorf("marshal presentation definition: %w", err)
	}

	presentations, err := f.wallet.Query(b, false)
	if err != nil {
		return "", fmt.Errorf("query wallet: %w", err)
	}

	if len(presentations) == 0 || len(presentations[0].Credentials()) == 0 {
		return "", fmt.Errorf("no attestation vc found")
	}

	attestationVC := presentations[0].Credentials()[0]

	attestationVP, err := verifiable.NewPresentation(verifiable.WithCredentials(attestationVC))
	if err != nil {
		return "", fmt.Errorf("create vp: %w", err)
	}

	attestationVP.ID = uuid.New().String()

	claims, err := attestationVP.JWTClaims([]string{}, false)
	if err != nil {
		return "", fmt.Errorf("get attestation claims: %w", err)
	}

	headers := map[string]interface{}{
		jose.HeaderType: jwtProofTypeHeader,
	}

	signedJWT, err := jwt.NewJoseSigned(claims, headers, f.signer)
	if err != nil {
		return "", fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serialize signed jwt: %w", err)
	}

	return jws, nil
}

func (f *Flow) receiveVC(
	token *oauth2.Token,
	wellKnown *issuerv1.WellKnownOpenIDIssuerConfiguration,
	credentialOfferResponse *oidc4ci.CredentialOfferResponse,
	credentialIssuer string,
) ([]*verifiable.Credential, error) {
	start := time.Now()
	defer func() {
		f.perfInfo.GetCredential = time.Since(start)
	}()

	proof, err := f.buildProof(token, credentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("build proof: %w", err)
	}

	credentialFilters, err := f.getCredentialRequestOIDCCredentialFilters(credentialOfferResponse, wellKnown)
	if err != nil {
		return nil, fmt.Errorf("getCredentialRequestOIDCCredentialFormat: %w", err)
	}

	var parseCredentialResponseDataList []*parseCredentialResponseData

	canUseBatchCredentialsEndpoint := lo.FromPtr(wellKnown.BatchCredentialEndpoint) != "" && len(credentialFilters) > 1

	if canUseBatchCredentialsEndpoint || f.useBatchCredentialsEndpoint {
		batchCredentialEndpoint := lo.FromPtr(wellKnown.BatchCredentialEndpoint)
		if batchCredentialEndpoint == "" {
			return nil, errors.New("BatchCredentialEndpoint is not enalbed for given profile")
		}

		slog.Info("Getting batch credential",
			"batch_credential_endpoint", batchCredentialEndpoint,
			"credential_issuer", credentialIssuer,
		)

		credentialResp, err := f.batchCredentialRequest(
			batchCredentialEndpoint,
			token,
			credentialFilters,
			proof,
		)
		if err != nil {
			return nil, fmt.Errorf("batchCredentialRequest: %w", err)
		}

		for _, credentialData := range credentialResp.CredentialResponses {
			parseCredentialResponseDataList = append(parseCredentialResponseDataList,
				&parseCredentialResponseData{
					credential:     credentialData.Credential,
					notificationID: credentialData.NotificationId,
				})
		}

	} else {
		credentialEndpoint := lo.FromPtr(wellKnown.CredentialEndpoint)
		slog.Info("Getting credential",
			"credential_endpoint", credentialEndpoint,
			"credential_issuer", credentialIssuer,
		)

		if len(credentialFilters) == 0 {
			return nil, errors.New("no credential filters defined")
		}

		credentialResp, err := f.credentialRequest(
			credentialEndpoint,
			token,
			credentialFilters[0].oidcCredentialFormat,
			credentialFilters[0].credentialType,
			proof,
		)
		if err != nil {
			return nil, fmt.Errorf("credentialRequest: %w", err)
		}

		parseCredentialResponseDataList = append(parseCredentialResponseDataList,
			&parseCredentialResponseData{
				credential:     credentialResp.Credential,
				notificationID: credentialResp.NotificationId,
			})
	}

	credentials, err := f.parseCredentialsResponse(parseCredentialResponseDataList, token, wellKnown)
	if err != nil {
		return nil, fmt.Errorf("parseCredentialsResponse: %w", err)
	}

	return credentials, nil
}

func (f *Flow) credentialRequest(
	credentialEndpoint string,
	token *oauth2.Token,
	credentialFormat vcsverifiable.OIDCFormat,
	credentialType string,
	proof *Proof,
) (*CredentialResponse, error) {
	b, err := json.Marshal(CredentialRequest{
		Format: credentialFormat,
		CredentialDefinition: &CredentialDefinition{
			Type: []string{"VerifiableCredential", credentialType},
		},
		CredentialIdentifier:         nil, // not supported for now
		Proof:                        *proof,
		CredentialResponseEncryption: nil, // not supported for now
	})
	if err != nil {
		return nil, fmt.Errorf("marshal credential request: %w", err)
	}

	responseBody, err := f.doCredentialRequest(credentialEndpoint, b, token)
	if err != nil {
		return nil, fmt.Errorf("doCredentialRequest: %w", err)
	}

	var credentialResp CredentialResponse

	if err = json.Unmarshal(responseBody, &credentialResp); err != nil {
		return nil, fmt.Errorf("decode credential response: %w", err)
	}

	return &credentialResp, nil
}

func (f *Flow) batchCredentialRequest(
	credentialEndpoint string,
	token *oauth2.Token,
	credentialFilters []*credentialFilter,
	proof *Proof,
) (*BatchCredentialResponse, error) {
	batchCredentialRequest := BatchCredentialRequest{
		CredentialRequests: make([]CredentialRequest, 0, len(credentialFilters)),
	}

	for _, filter := range credentialFilters {
		req := CredentialRequest{
			Format: filter.oidcCredentialFormat,
			CredentialDefinition: &CredentialDefinition{
				Type: []string{"VerifiableCredential", filter.credentialType},
			},
			CredentialIdentifier:         nil, // not supported for now
			Proof:                        *proof,
			CredentialResponseEncryption: nil, // not supported for now.
		}
		batchCredentialRequest.CredentialRequests = append(batchCredentialRequest.CredentialRequests, req)
	}

	b, err := json.Marshal(batchCredentialRequest)
	if err != nil {
		return nil, fmt.Errorf("marshal batch credential request: %w", err)
	}

	responseBody, err := f.doCredentialRequest(credentialEndpoint, b, token)
	if err != nil {
		return nil, fmt.Errorf("doCredentialRequest: %w", err)
	}

	var batchCredentialResponse BatchCredentialResponse

	if err = json.Unmarshal(responseBody, &batchCredentialResponse); err != nil {
		return nil, fmt.Errorf("decode batch credential response: %w", err)
	}

	return &batchCredentialResponse, nil
}

func (f *Flow) parseCredentialsResponse(
	parseCredentialResponseDataList []*parseCredentialResponseData,
	token *oauth2.Token,
	wellKnown *issuerv1.WellKnownOpenIDIssuerConfiguration,
) ([]*verifiable.Credential, error) {
	notificationIDs := make([]string, 0, len(parseCredentialResponseDataList))
	credentials := make([]*verifiable.Credential, 0, len(parseCredentialResponseDataList))

	for i, parseCredentialData := range parseCredentialResponseDataList {
		vcBytes, err := json.Marshal(parseCredentialData.credential)
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

		if err = f.wallet.Add(vcBytes, fmt.Sprintf("%s_%d", parsedVC.Contents().Types[1], i)); err != nil {
			return nil, fmt.Errorf("add credential to wallet: %w", err)
		}

		var cslURL, statusListIndex, statusListType string

		if vcc := parsedVC.Contents(); vcc.Status != nil && vcc.Status.CustomFields != nil {
			statusListType = vcc.Status.Type

			u, ok := vcc.Status.CustomFields["statusListCredential"].(string)
			if ok {
				cslURL = u
			}

			i, ok := vcc.Status.CustomFields["statusListIndex"].(string)
			if ok {
				statusListIndex = i
			}
		}

		predicate := func(item string, i int) bool {
			return !strings.EqualFold(item, "VerifiableCredential")
		}

		slog.Info("credential added to wallet",
			"credential_id", parsedVC.Contents().ID,
			"credential_type", strings.Join(lo.Filter(parsedVC.Contents().Types, predicate), ","),
			"issuer_id", parsedVC.Contents().Issuer.ID,
			"csl_url", cslURL,
			"status_list_index", statusListIndex,
			"status_list_type", statusListType,
		)

		credentials = append(credentials, parsedVC)
		notificationIDs = append(notificationIDs, lo.FromPtr(parseCredentialData.notificationID))
	}

	if err := f.handleIssuanceAck(wellKnown, notificationIDs, token); err != nil {
		return nil, fmt.Errorf("handleIssuanceAck: %w", err)
	}

	return credentials, nil
}

func (f *Flow) buildProof(
	token *oauth2.Token,
	credentialIssuer string,
) (*Proof, error) {
	claims := &ProofClaims{
		Issuer:   f.clientID,
		IssuedAt: lo.ToPtr(time.Now().Unix()),
		Audience: credentialIssuer,
		Nonce:    token.Extra("c_nonce").(string),
	}

	return f.proofBuilder.Build(context.TODO(), &CreateProofRequest{
		Signer:           f.signer,
		CustomHeaders:    map[string]interface{}{},
		WalletKeyID:      f.walletKeyID,
		WalletKeyType:    f.walletKeyType,
		Claims:           claims,
		VDR:              f.vdrRegistry,
		WalletDID:        f.wallet.DIDs()[0].ID,
		CredentialIssuer: credentialIssuer,
	})
}

func (f *Flow) doCredentialRequest(
	credentialEndpoint string,
	requestPayload []byte,
	token *oauth2.Token,
) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, credentialEndpoint, bytes.NewBuffer(requestPayload))
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

	var responseBody []byte
	if responseBody, err = io.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"get credential: status %s and body %s",
			resp.Status,
			string(responseBody),
		)
	}

	return responseBody, nil
}

// getCredentialRequestOIDCCredentialFilters returns list of credentialType and credentialFormat pairs
// used for Credential request or Batch Credential request.
func (f *Flow) getCredentialRequestOIDCCredentialFilters(
	credentialOfferResponse *oidc4ci.CredentialOfferResponse,
	wellKnown *issuerv1.WellKnownOpenIDIssuerConfiguration,
) ([]*credentialFilter, error) {
	// Take default value as f.credentialFilters
	if len(f.credentialFilters) > 0 {
		return f.credentialFilters, nil
	}

	// CredentialFilters is not supplied:

	if len(f.credentialConfigurationIDs) > 0 {
		// CredentialConfigurationID option available so take format from well-known configuration.
		return f.getCredentialFiltersFromCredentialConfigurationIDs(f.credentialConfigurationIDs, wellKnown)
	}

	if len(f.scopes) > 0 {
		var credentialFilters []*credentialFilter

		// scopes option available so take format from well-known configuration.
		// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.2
		for _, scope := range f.scopes {
			for _, credentialConfiguration := range wellKnown.CredentialConfigurationsSupported.AdditionalProperties {
				if lo.FromPtr(credentialConfiguration.Scope) != scope {
					continue
				}

				format := vcsverifiable.OIDCFormat(credentialConfiguration.Format)

				if credentialConfiguration.CredentialDefinition == nil {
					return nil, fmt.Errorf(
						"unable to obtain credential type from issuer well-known configuration. "+
							"Check if `issuer.credentialMetadata.credential_configurations_supported` contains key `%s` "+
							"with nested `credential_definition` field", f.credentialConfigurationIDs[0])
				}

				credentialType, ok := lo.Find(credentialConfiguration.CredentialDefinition.Type, func(item string) bool {
					return item != "VerifiableCredential"
				})
				if !ok {
					return nil, fmt.Errorf(
						"unable to get credential type using credential configuration ID %s", f.credentialConfigurationIDs[0])
				}

				credentialFilters = append(credentialFilters, &credentialFilter{
					credentialType:       credentialType,
					oidcCredentialFormat: vcsverifiable.OIDCFormat(format),
				})
			}
		}

		return credentialFilters, nil
	}

	// Get credential filter from credential offer.
	return f.getCredentialFiltersFromCredentialConfigurationIDs(
		credentialOfferResponse.CredentialConfigurationIDs, wellKnown)
}

func (f *Flow) getCredentialFiltersFromCredentialConfigurationIDs(
	credentialConfigurationIDs []string,
	wellKnown *issuerv1.WellKnownOpenIDIssuerConfiguration,
) ([]*credentialFilter, error) {
	var credentialFilters []*credentialFilter

	for _, credentialConfigurationID := range credentialConfigurationIDs {
		credentialConf := wellKnown.CredentialConfigurationsSupported.AdditionalProperties[credentialConfigurationID]
		format := credentialConf.Format
		if format == "" {
			return nil, fmt.Errorf(
				"unable to obtain OIDC credential format from issuer well-known configuration. "+
					"Check if `issuer.credentialMetadata.credential_configurations_supported` contains key `%s` "+
					"with nested `format` field", credentialConfigurationID)
		}

		if credentialConf.CredentialDefinition == nil {
			return nil, fmt.Errorf(
				"unable to obtain credential type from issuer well-known configuration. "+
					"Check if `issuer.credentialMetadata.credential_configurations_supported` contains key `%s` "+
					"with nested `credential_definition` field", credentialConfigurationID)
		}

		credentialType, ok := lo.Find(credentialConf.CredentialDefinition.Type, func(item string) bool {
			return item != "VerifiableCredential"
		})
		if !ok {
			return nil, fmt.Errorf(
				"unable to get credential type using credential configuration ID %s", credentialConfigurationID)
		}

		credentialFilters = append(credentialFilters, &credentialFilter{
			credentialType:       credentialType,
			oidcCredentialFormat: vcsverifiable.OIDCFormat(format),
		})
	}

	return credentialFilters, nil
}

func (f *Flow) handleIssuanceAck(
	wellKnown *issuerv1.WellKnownOpenIDIssuerConfiguration,
	notificationIDs []string,
	token *oauth2.Token,
) error {
	if wellKnown == nil || len(notificationIDs) == 0 {
		return nil
	}

	notificationEndpoint := lo.FromPtr(wellKnown.NotificationEndpoint)
	if notificationEndpoint == "" {
		return nil
	}

	start := time.Now()
	defer func() {
		f.perfInfo.CredentialsAck = time.Since(start)
	}()

	slog.Info("Sending wallet notification",
		"notification_ids", notificationIDs,
		"endpoint", notificationEndpoint,
	)

	ackRequest := oidc4civ1.AckRequest{
		Credentials: []oidc4civ1.AcpRequestItem{},
	}

	for _, notificationID := range notificationIDs {
		if notificationID == "" {
			continue
		}

		ackRequest.Credentials = append(ackRequest.Credentials, oidc4civ1.AcpRequestItem{
			Event:            "credential_accepted",
			EventDescription: nil,
			IssuerIdentifier: wellKnown.CredentialIssuer,
			NotificationId:   notificationID,
		})
	}

	b, err := json.Marshal(ackRequest)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, notificationEndpoint, bytes.NewBuffer(b))
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

// getAuthorizationDetailsRequestBody returns authorization details request body
// used in FlowTypeAuthorizationCode or FlowTypeWalletInitiated.
// Returned value is depended on incoming params: credential_configuration_ids, credential offer response or credential filter params.
// If none of them supplied, Wallet CLI should use scope parameter to request credential type:
// https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.2
//
// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.1
func (f *Flow) getAuthorizationDetailsRequestBody() ([]byte, error) {
	res := make([]common.AuthorizationDetails, 0)

	switch {
	case len(f.credentialConfigurationIDs) > 0: // Priority 1. Based on credentialConfigurationIDs.
		for _, credentialConfigurationID := range f.credentialConfigurationIDs {
			res = append(res, common.AuthorizationDetails{
				CredentialConfigurationId: lo.ToPtr(credentialConfigurationID),
				CredentialDefinition:      nil,
				Format:                    nil,
				Locations:                 nil, // Not supported for now.
				Type:                      "openid_credential",
			})
		}
	case len(f.credentialFilters) > 0: // Priority 2. Based on credentialFilters (credentialType & credentialFormat pairs).
		for _, cr := range f.credentialFilters {
			res = append(res, common.AuthorizationDetails{
				CredentialConfigurationId: nil,
				CredentialDefinition: &common.CredentialDefinition{
					Context:           nil, // Not supported for now.
					CredentialSubject: nil, // Not supported for now.
					Type: []string{
						"VerifiableCredential",
						cr.credentialType,
					},
				},
				Format:    lo.ToPtr(string(cr.oidcCredentialFormat)),
				Locations: nil, // Not supported for now.
				Type:      "openid_credential",
			})
		}
	default:
		// Valid case - neither credentialFilters nor credentialConfigurationID supplied.
		return nil, nil
	}

	return json.Marshal(res)
}

func (f *Flow) PerfInfo() *PerfInfo {
	return f.perfInfo
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
	flowType                    FlowType
	proofBuilder                ProofBuilder
	credentialOffer             string
	clientID                    string
	credentialConfigurationIDs  []string
	scopes                      []string
	redirectURI                 string
	enableDiscoverableClientID  bool
	useBatchCredentialsEndpoint bool
	userLogin                   string
	userPassword                string
	issuerState                 string
	pin                         string
	walletDIDIndex              int
	credentialFilters           []*credentialFilter
}

type Opt func(opts *options)

func WithFlowType(flowType FlowType) Opt {
	return func(opts *options) {
		opts.flowType = flowType
	}
}

func WithProofBuilder(proofBuilder ProofBuilder) Opt {
	return func(opts *options) {
		opts.proofBuilder = proofBuilder
	}
}

func WithCredentialOffer(credentialOffer string) Opt {
	return func(opts *options) {
		opts.credentialOffer = credentialOffer
	}
}

func WithCredentialFilter(credentialType string, oidcCredentialFormat vcsverifiable.OIDCFormat) Opt {
	return func(opts *options) {
		opts.credentialFilters = append(opts.credentialFilters, &credentialFilter{
			credentialType:       credentialType,
			oidcCredentialFormat: oidcCredentialFormat,
		})
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

func WithBatchCredentialIssuance() Opt {
	return func(opts *options) {
		opts.useBatchCredentialsEndpoint = true
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

func WithWalletDIDIndex(idx int) Opt {
	return func(opts *options) {
		opts.walletDIDIndex = idx
	}
}

func WithCredentialConfigurationIDs(credentialConfigurationIDs []string) Opt {
	return func(opts *options) {
		opts.credentialConfigurationIDs = credentialConfigurationIDs
	}
}
