/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package oidc4ci_test . StateStore,OAuth2Provider,IssuerInteractionClient,HTTPClient,ClientManager,ProfileService,AckService,CwtProofChecker,LDPProofParser

package oidc4ci

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/fxamacker/cbor/v2"
	gojose "github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/cwt"
	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/suite/ecdsa2019"
	"github.com/trustbloc/vc-go/dataintegrity/suite/eddsa2022"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/veraison/go-cose"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4cierr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4ci"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc6749"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc7591"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/clientidscheme"
	"github.com/trustbloc/vcs/pkg/service/clientmanager"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	sessionOpStateKey          = "opState"
	authorizationDetailsKey    = "authDetails"
	txIDKey                    = "txID"
	preAuthKey                 = "preAuth"
	preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	discoverableClientIDScheme = "urn:ietf:params:oauth:client-id-scheme:oauth-discoverable-client"
	jwtProofTypHeader          = "openid4vci-proof+jwt"
	cwtProofTypHeader          = "application/openid4vci-proof+cwt"
	cNonceKey                  = "cNonce"
	cNonceExpiresAtKey         = "cNonceExpiresAt"
	cNonceSize                 = 15
	cNonceTTL                  = 5 * time.Minute

	proofTypeCWT   = "cwt"
	proofTypeJWT   = "jwt"
	proofTypeLDPVP = "ldp_vp"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

var logger = log.New("oidc4ci")

// StateStore stores authorization request/response state.
type StateStore interface {
	SaveAuthorizeState(
		ctx context.Context,
		profileAuthStateTTL int32,
		opState string,
		state *oidc4ci.AuthorizeState,
	) error

	GetAuthorizeState(ctx context.Context, opState string) (*oidc4ci.AuthorizeState, error)
}

// HTTPClient defines HTTP client interface.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// OAuth2Provider provides functionality for OAuth2 handlers.
type OAuth2Provider fosite.OAuth2Provider

// IssuerInteractionClient defines API client for interaction with issuer private API.
type IssuerInteractionClient issuer.ClientInterface

// ClientManager defines client manager interface.
type ClientManager clientmanager.ServiceInterface

// ClientIDSchemeService defines OAuth 2.0 Client ID Scheme service interface.
type ClientIDSchemeService clientidscheme.ServiceInterface

// ProfileService defines issuer profile service interface.
type ProfileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error)
}

type CwtProofChecker interface {
	CheckCWTProof(
		checkCWTRequest checker.CheckCWTProofRequest,
		expectedProofIssuer string,
		msg []byte,
		signature []byte,
	) error
}

type AckService interface {
	Ack(ctx context.Context, req oidc4ci.AckRemote) error // *oidc4cierr.Error
}

type LDPProofParser interface {
	Parse(
		rawProof []byte,
		opt []verifiable.PresentationOpt,
	) (*verifiable.Presentation, error)
}

// JWEEncrypterCreator creates JWE encrypter for given JWK, alg and enc.
type JWEEncrypterCreator func(jwk gojose.JSONWebKey, alg gojose.KeyAlgorithm, enc gojose.ContentEncryption) (gojose.Encrypter, error) //nolint:lll

// Config holds configuration options for Controller.
type Config struct {
	OAuth2Provider          OAuth2Provider
	StateStore              StateStore
	HTTPClient              HTTPClient
	IssuerInteractionClient IssuerInteractionClient
	ProfileService          ProfileService
	ClientManager           ClientManager
	ClientIDSchemeService   ClientIDSchemeService
	JWTVerifier             jwt.ProofChecker
	CWTVerifier             CwtProofChecker
	Tracer                  trace.Tracer
	IssuerVCSPublicHost     string
	ExternalHostURL         string
	AckService              AckService
	JWEEncrypterCreator     JWEEncrypterCreator

	DocumentLoader ld.DocumentLoader
	Vdr            vdrapi.Registry
	ProofChecker   *checker.ProofChecker
	LDPProofParser LDPProofParser
}

// Controller for OIDC credential issuance API.
type Controller struct {
	oauth2Provider          OAuth2Provider
	stateStore              StateStore
	httpClient              HTTPClient
	issuerInteractionClient IssuerInteractionClient
	profileService          ProfileService
	clientManager           ClientManager
	clientIDSchemeService   ClientIDSchemeService
	jwtVerifier             jwt.ProofChecker
	cwtVerifier             CwtProofChecker
	tracer                  trace.Tracer
	issuerVCSPublicHost     string
	internalHostURL         string
	ackService              AckService
	jweEncrypterCreator     JWEEncrypterCreator

	documentLoader ld.DocumentLoader
	vdr            vdrapi.Registry
	proofCheker    *checker.ProofChecker
	ldpProofParser LDPProofParser
}

// NewController creates a new Controller instance.
func NewController(config *Config) *Controller {
	return &Controller{
		oauth2Provider:          config.OAuth2Provider,
		stateStore:              config.StateStore,
		httpClient:              config.HTTPClient,
		issuerInteractionClient: config.IssuerInteractionClient,
		profileService:          config.ProfileService,
		clientManager:           config.ClientManager,
		clientIDSchemeService:   config.ClientIDSchemeService,
		jwtVerifier:             config.JWTVerifier,
		cwtVerifier:             config.CWTVerifier,
		tracer:                  config.Tracer,
		issuerVCSPublicHost:     config.IssuerVCSPublicHost,
		internalHostURL:         config.ExternalHostURL,
		ackService:              config.AckService,
		jweEncrypterCreator:     config.JWEEncrypterCreator,
		documentLoader:          config.DocumentLoader,
		vdr:                     config.Vdr,
		proofCheker:             config.ProofChecker,
		ldpProofParser:          config.LDPProofParser,
	}
}

// OidcPushedAuthorizationRequest handles OIDC pushed authorization request (POST /oidc/par).
//
// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-5.1.4
//
// Success response: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
//
// Error responses (resterr.FositeError): https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
func (c *Controller) OidcPushedAuthorizationRequest(e echo.Context) error {
	req := e.Request()
	ctx := req.Context()

	ar, err := c.oauth2Provider.NewPushedAuthorizeRequest(ctx, req)
	if err != nil {
		return resterr.NewFositeError(resterr.FositePARError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	var par PushedAuthorizationRequest

	if err = e.Bind(&par); err != nil {
		logger.Errorc(ctx, "decode PAR", log.WithError(err))

		return resterr.NewFositePARInvalidRequestErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
	}

	var ad []common.AuthorizationDetails

	if err = json.Unmarshal([]byte(par.AuthorizationDetails), &ad); err != nil {
		logger.Errorc(ctx, "decode authorization details", log.WithError(err))

		return resterr.NewFositePARInvalidRequestErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
	}

	_, err = apiUtil.ValidateAuthorizationDetails(ad)
	if err != nil {
		logger.Errorc(ctx, "validate authorization details", log.WithError(err))

		return resterr.NewFositePARInvalidRequestErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
	}

	r, err := c.issuerInteractionClient.PushAuthorizationDetails(ctx,
		issuer.PushAuthorizationDetailsJSONRequestBody{
			AuthorizationDetails: ad,
			OpState:              par.OpState,
		},
	)
	if err != nil {
		logger.Errorc(ctx, "push authorization details", log.WithError(err))

		return resterr.NewFositePARUnauthorizedClientErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
	}

	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		logger.Errorc(ctx,
			fmt.Sprintf("push authorization details: status code %d", r.StatusCode),
			log.WithError(rfc6749.Parse(r.Body)))

		return resterr.NewFositePARUnauthorizedClientErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
	}

	resp, err := c.oauth2Provider.NewPushedAuthorizeResponse(ctx, ar, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewFositeError(resterr.FositePARError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	c.oauth2Provider.WritePushedAuthorizeResponse(ctx, e.Response().Writer, ar, resp)

	return nil
}

// OidcAuthorize handles OIDC authorization request (GET /oidc/authorize).
//
// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-5.1
//
// Success response: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
//
// Error responses (resterr.FositeError): https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
func (c *Controller) OidcAuthorize(e echo.Context, params OidcAuthorizeParams) error { //nolint:funlen,gocognit
	req := e.Request()
	ctx := req.Context()

	if lo.FromPtr(params.IssuerState) == "" {
		params.IssuerState = lo.ToPtr(uuid.NewString())
	}

	if lo.FromPtr(params.ClientIdScheme) == discoverableClientIDScheme {
		if err := c.clientIDSchemeService.Register(ctx, params.ClientId, lo.FromPtr(params.IssuerState)); err != nil {
			logger.Errorc(ctx, "register discoverable client", log.WithError(err))

			return resterr.NewFositeAuthUnauthorizedClientErr(e, c.oauth2Provider).
				WithAuthorizeRequester(fosite.NewAuthorizeRequest())
		}
	}

	ar, err := c.oauth2Provider.NewAuthorizeRequest(ctx, req)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	ses := &fosite.DefaultSession{
		Extra: map[string]interface{}{
			sessionOpStateKey:       lo.FromPtr(params.IssuerState),
			authorizationDetailsKey: lo.FromPtr(params.AuthorizationDetails),
		},
	}

	var prepareAuthRequestAuthorizationDetails *[]common.AuthorizationDetails

	if params.AuthorizationDetails != nil {
		var authorizationDetails []common.AuthorizationDetails
		if err = json.Unmarshal([]byte(*params.AuthorizationDetails), &authorizationDetails); err != nil {
			logger.Errorc(ctx, "decode authorization details", log.WithError(err))

			return resterr.NewFositeAuthInvalidRequestErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
		}

		if _, err = apiUtil.ValidateAuthorizationDetails(authorizationDetails); err != nil {
			logger.Errorc(ctx, "validate authorization details", log.WithError(err))

			return resterr.NewFositeAuthInvalidRequestErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
		}

		prepareAuthRequestAuthorizationDetails = lo.ToPtr(authorizationDetails)
	}

	r, err := c.issuerInteractionClient.PrepareAuthorizationRequest(ctx,
		issuer.PrepareAuthorizationRequestJSONRequestBody{
			AuthorizationDetails: prepareAuthRequestAuthorizationDetails,
			OpState:              lo.FromPtr(params.IssuerState),
			ResponseType:         params.ResponseType,
			Scope:                lo.ToPtr([]string(ar.GetRequestedScopes())),
		},
	)
	if err != nil {
		logger.Errorc(ctx, "prepare authorization request", log.WithError(err))

		return resterr.NewFositeAuthUnauthorizedClientErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
	}

	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		logger.Errorc(ctx,
			fmt.Sprintf("prepare claim data authorization: status code %d", r.StatusCode),
			log.WithError(rfc6749.Parse(r.Body)))

		return resterr.NewFositeAuthUnauthorizedClientErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
	}

	var claimDataAuth issuer.PrepareClaimDataAuthorizationResponse

	if err = json.NewDecoder(r.Body).Decode(&claimDataAuth); err != nil {
		logger.Errorc(ctx, "decode claim data authorization response", log.WithError(err))

		return resterr.NewFositeAuthUnauthorizedClientErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
	}

	if claimDataAuth.WalletInitiatedFlow != nil {
		ses.Extra[sessionOpStateKey] = claimDataAuth.WalletInitiatedFlow.OpState // swap op state
		params.IssuerState = &claimDataAuth.WalletInitiatedFlow.OpState
	}

	if params.State != nil {
		ar.(*fosite.AuthorizeRequest).State = *params.State // nolint
	}

	resp, err := c.oauth2Provider.NewAuthorizeResponse(ctx, ar, ses)
	if err != nil {
		logger.Errorc(ctx, "new authorize response", log.WithError(err))

		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	if err = c.stateStore.SaveAuthorizeState(
		ctx,
		int32(claimDataAuth.ProfileAuthStateTtl), //nolint:gosec
		lo.FromPtr(params.IssuerState),
		&oidc4ci.AuthorizeState{
			RedirectURI:         ar.GetRedirectURI(),
			RespondMode:         string(ar.GetResponseMode()),
			Header:              resp.GetHeader(),
			Parameters:          resp.GetParameters(),
			WalletInitiatedFlow: claimDataAuth.WalletInitiatedFlow,
		}); err != nil {
		logger.Errorc(ctx, "save authorize state", log.WithError(err))

		return resterr.NewFositeAuthUnauthorizedClientErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
	}

	oauthConfig := oauth2.Config{
		ClientID:     claimDataAuth.AuthorizationRequest.ClientId,
		ClientSecret: claimDataAuth.AuthorizationRequest.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   claimDataAuth.AuthorizationEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: c.issuerVCSPublicHost + "/oidc/redirect",
		Scopes:      claimDataAuth.AuthorizationRequest.Scope,
	}

	var authCodeURL string

	if len(lo.FromPtr(claimDataAuth.PushedAuthorizationRequestEndpoint)) > 0 {
		authCodeURL, err = c.buildAuthCodeURLWithPAR(ctx,
			oauthConfig,
			*claimDataAuth.PushedAuthorizationRequestEndpoint,
			lo.FromPtr(params.IssuerState),
		)
		if err != nil {
			logger.Errorc(ctx, "build Auth code URL with PAR", log.WithError(err))

			return resterr.NewFositeAuthUnauthorizedClientErr(e, c.oauth2Provider).WithAuthorizeRequester(ar)
		}
	} else {
		authCodeURL = oauthConfig.AuthCodeURL(lo.FromPtr(params.IssuerState))
	}

	return e.Redirect(http.StatusSeeOther, authCodeURL)
}

type parResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (c *Controller) buildAuthCodeURLWithPAR(
	ctx context.Context,
	cfg oauth2.Config,
	parEndpoint string,
	state string,
) (string, error) {
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {cfg.ClientID},
		"state":         {state},
	}

	if cfg.RedirectURL != "" {
		v.Set("redirect_uri", cfg.RedirectURL)
	}

	if len(cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(cfg.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req.WithContext(ctx)) //nolint:bodyclose // closed in defer
	if err != nil {
		return "", fmt.Errorf("post form: %w", err)
	}

	defer func(Body io.ReadCloser) {
		if err = Body.Close(); err != nil {
			logger.Errorc(ctx, "Failed to close response body", log.WithError(err))
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected status code %v", resp.StatusCode)
	}

	var response parResponse
	if err = json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("decode par response: %w", err)
	}

	return fmt.Sprintf("%v?%v",
		cfg.Endpoint.AuthURL,
		url.Values{
			"client_id":   {cfg.ClientID},
			"request_uri": {response.RequestURI},
		}.Encode(),
	), nil
}

// OidcRedirect handles OIDC redirect (GET /oidc/redirect).
func (c *Controller) OidcRedirect(e echo.Context, params OidcRedirectParams) error {
	req := e.Request()
	ctx := req.Context()

	resp, err := c.stateStore.GetAuthorizeState(ctx, params.State)
	if err != nil {
		return rfc6749.NewUnauthorizedClientError(err).UsePublicAPIResponse()
	}

	storeResp, err := c.issuerInteractionClient.StoreAuthorizationCodeRequest(ctx,
		issuer.StoreAuthorizationCodeRequestJSONRequestBody{
			Code:                params.Code,
			OpState:             params.State,
			WalletInitiatedFlow: resp.WalletInitiatedFlow,
		})
	if err != nil {
		return rfc6749.NewUnauthorizedClientError(err).UsePublicAPIResponse()
	}

	defer storeResp.Body.Close()

	if storeResp.StatusCode != http.StatusOK {
		return rfc6749.Parse(storeResp.Body).
			WithErrorPrefix(fmt.Sprintf("store authorization code request: status code %d", storeResp.StatusCode)).
			UsePublicAPIResponse()
	}

	responder := &fosite.AuthorizeResponse{}
	responder.Header = resp.Header
	responder.Parameters = resp.Parameters

	c.oauth2Provider.WriteAuthorizeResponse(ctx, e.Response().Writer, &fosite.AuthorizeRequest{
		RedirectURI:         resp.RedirectURI,
		ResponseMode:        fosite.ResponseModeType(resp.RespondMode),
		DefaultResponseMode: fosite.ResponseModeType(resp.RespondMode),
		State:               params.State,
	}, responder)

	return nil
}

// OidcToken handles OIDC token request (POST /oidc/token).
//
// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-6.1 and
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
//
// Success response: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-6.2
//
// Error responses: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
func (c *Controller) OidcToken(e echo.Context) error {
	req := e.Request()

	ctx, span := c.tracer.Start(req.Context(), "OidcToken")
	defer span.End()

	ar, err := c.oauth2Provider.NewAccessRequest(ctx, req, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAccessError, e, c.oauth2Provider, err).WithAccessRequester(ar)
	}

	session := ar.GetSession().(*fosite.DefaultSession) //nolint:errcheck
	if session.Extra == nil {
		session.Extra = make(map[string]interface{})
	}

	nonce := mustGenerateNonce()
	var txID string
	var authorisationDetails *[]common.AuthorizationDetails

	isPreAuthFlow := strings.EqualFold(e.FormValue("grant_type"), preAuthorizedCodeGrantType)
	if isPreAuthFlow { //nolint:nestif
		resp, preAuthorizeErr := c.oidcPreAuthorizedCode(
			ctx,
			e.FormValue("pre-authorized_code"),
			e.FormValue("tx_code"),
			e.FormValue("client_id"),
			e.FormValue("client_assertion_type"),
			e.FormValue("client_assertion"),
		)

		if preAuthorizeErr != nil {
			return preAuthorizeErr.UsePublicAPIResponse()
		}

		txID = resp.TxId
		authorisationDetails = resp.AuthorizationDetails
	} else {
		exchangeResp, errExchange := c.issuerInteractionClient.ExchangeAuthorizationCodeRequest(
			ctx,
			issuer.ExchangeAuthorizationCodeRequestJSONRequestBody{
				OpState:             ar.GetSession().(*fosite.DefaultSession).Extra[sessionOpStateKey].(string), // nolint
				ClientId:            lo.ToPtr(ar.GetClient().GetID()),
				ClientAssertionType: lo.ToPtr(e.FormValue("client_assertion_type")),
				ClientAssertion:     lo.ToPtr(e.FormValue("client_assertion")),
			},
		)
		if errExchange != nil {
			return rfc6749.NewInvalidGrantError(errExchange).
				WithErrorPrefix("exchange authorization code request").
				UsePublicAPIResponse()
		}

		defer exchangeResp.Body.Close()

		if exchangeResp.StatusCode != http.StatusOK {
			return rfc6749.Parse(exchangeResp.Body).
				WithErrorPrefix("exchange authorization code request").
				UsePublicAPIResponse()
		}

		var exchangeResult issuer.ExchangeAuthorizationCodeResponse

		if err = json.NewDecoder(exchangeResp.Body).Decode(&exchangeResult); err != nil {
			return rfc6749.NewInvalidRequestError(err).
				WithErrorPrefix("read exchange auth code response").
				UsePublicAPIResponse()
		}

		txID = exchangeResult.TxId
		authorisationDetails = exchangeResult.AuthorizationDetails
	}

	c.setCNonceSession(session, nonce, txID, isPreAuthFlow)

	responder, err := c.oauth2Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAccessError, e, c.oauth2Provider, err).WithAccessRequester(ar)
	}

	c.setCNonce(responder, nonce)

	if authorisationDetails != nil {
		c.setAuthorizationDetails(responder, authorisationDetails)
	}

	c.oauth2Provider.WriteAccessResponse(ctx, e.Response().Writer, ar, responder)

	return nil
}

func (c *Controller) setCNonce(
	responder fosite.AccessResponder,
	nonce string,
) {
	responder.SetExtra("c_nonce", nonce)
	responder.SetExtra("c_nonce_expires_in", cNonceTTL.Seconds())
}

func (c *Controller) setAuthorizationDetails(
	responder fosite.AccessResponder,
	authorisationDetails *[]common.AuthorizationDetails,
) {
	responder.SetExtra("authorization_details", authorisationDetails)
}

func (c *Controller) setCNonceSession(
	session *fosite.DefaultSession,
	nonce string,
	txID string,
	isPreAuthFlow bool,
) {
	session.Extra[txIDKey] = txID
	session.Extra[preAuthKey] = isPreAuthFlow
	session.Extra[cNonceKey] = nonce
	session.Extra[cNonceExpiresAtKey] = time.Now().Add(cNonceTTL).Unix()
}

func mustGenerateNonce() string {
	b := make([]byte, cNonceSize)

	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return base64.URLEncoding.EncodeToString(b)
}

// OidcAcknowledgement handles OIDC4CI acknowledgement request (POST /oidc/notification).
//
// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-10.1
//
// Success response: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-10.2
//
// Error responses: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-10.3 and
// https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
func (c *Controller) OidcAcknowledgement(e echo.Context) error {
	req := e.Request()

	var body AckRequest
	if err := e.Bind(&body); err != nil {
		return oidc4cierr.NewInvalidNotificationRequestError(err)
	}

	token := fosite.AccessTokenFromRequest(req)
	if token == "" {
		// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-10.3-1
		return resterr.NewFositeAccessTokenInvalidTokenErr(e, c.oauth2Provider)
	}

	// for now we dont need to introspect token as it can be expired.
	// todo: once new we have new spec add logic with token
	// _, _, err := c.oauth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, new(fosite.DefaultSession))
	// if err != nil {
	//	return resterr.NewOIDCError(invalidTokenOIDCErr, fmt.Errorf("introspect token: %w", err))
	// }

	ctx := req.Context()
	hashedToken := hashToken(token)
	interactionDetails := lo.FromPtr(body.InteractionDetails)

	if err := c.ackService.Ack(ctx, oidc4ci.AckRemote{
		TxID:               issuecredential.TxID(body.NotificationId),
		Event:              body.Event,
		HashedToken:        hashedToken,
		EventDescription:   lo.FromPtr(body.EventDescription),
		IssuerIdentifier:   lo.FromPtr(body.IssuerIdentifier),
		InteractionDetails: interactionDetails,
	}); err != nil {
		var oidc4ciErr *oidc4cierr.Error

		if !errors.As(err, &oidc4ciErr) {
			oidc4ciErr = oidc4cierr.NewInvalidNotificationRequestError(err)
		}

		return oidc4ciErr
	}

	return e.NoContent(http.StatusNoContent)
}

//nolint:funlen,gocognit
func (c *Controller) HandleProof(
	clientID string,
	credentialReq *CredentialRequest,
	session *fosite.DefaultSession,
) (string, string, error) { // *oidc4cierr.Error
	var proofClaims ProofClaims

	proofHeaders := ProofHeaders{
		ProofType: credentialReq.Proof.ProofType,
	}

	switch credentialReq.Proof.ProofType {
	case proofTypeJWT:
		jws, rawClaims, err := jwt.ParseAndCheckProof(lo.FromPtr(credentialReq.Proof.Jwt),
			c.jwtVerifier, false,
			jwt.WithIgnoreClaimsMapDecoding(true),
		)
		if err != nil {
			return "", "",
				oidc4cierr.NewInvalidProofError(err).WithErrorPrefix("parse jwt")
		}

		proofHeaders.Type, _ = jws.Headers.Type()
		proofHeaders.KeyID, _ = jws.Headers.KeyID()

		if err = json.Unmarshal(rawClaims, &proofClaims); err != nil {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(errors.New("invalid jwt claims"))
		}
	case proofTypeCWT:
		cwtBytes, err := hex.DecodeString(lo.FromPtr(credentialReq.Proof.Cwt))
		if err != nil {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(errors.New("invalid cwt"))
		}

		cwtParsed, rawClaims, err := cwt.ParseAndCheckProof(cwtBytes, c.cwtVerifier, false)
		if err != nil {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(err).WithErrorPrefix("parse cwt")
		}

		if err = cbor.Unmarshal(rawClaims, &proofClaims); err != nil {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(errors.New("invalid cwt claims"))
		}

		typ, ok := cwtParsed.Headers.Protected[cose.HeaderLabelContentType].(string)
		if !ok {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(errors.New("invalid COSE content type"))
		}
		proofHeaders.Type = typ

		keyBytes, ok := cwtParsed.Headers.Protected[proof.COSEKeyHeader].(string)
		if !ok {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(errors.New("invalid COSE_KEY"))
		}

		proofHeaders.KeyID = keyBytes
	case proofTypeLDPVP:
		if credentialReq.Proof.LdpVp == nil {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(errors.New("missing ldp_vp"))
		}

		rawProof, err := json.Marshal(*credentialReq.Proof.LdpVp)
		if err != nil {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(errors.New("invalid ldp_vp"))
		}

		ver, err := c.getDataIntegrityVerifier()
		if err != nil {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(err).WithErrorPrefix("get data integrity verifier")
		}

		presentationOpts := []verifiable.PresentationOpt{
			verifiable.WithPresDataIntegrityVerifier(ver),
			verifiable.WithPresProofChecker(c.proofCheker),
			verifiable.WithDisabledJSONLDChecks(),
		}

		if session != nil && len(session.Extra) > 0 {
			nonce := session.Extra[cNonceKey].(string) //nolint:errcheck
			if nonce != "" {
				presentationOpts = append(presentationOpts,
					verifiable.WithPresExpectedDataIntegrityFields("", "", nonce),
				)
			}
		}

		presentation, err := c.ldpProofParser.Parse(rawProof, presentationOpts)

		if err != nil {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(errors.New("can not parse ldp_vp as presentation"))
		}

		if len(presentation.Proofs) != 1 {
			return "", "",
				oidc4cierr.NewInvalidCredentialRequestError(
					fmt.Errorf("expected 1 proof, got %d", len(presentation.Proofs)))
		}

		proof := presentation.Proofs[0]

		proofHeaders.Type = "ldp_vp"
		proofHeaders.KeyID = presentation.Holder

		proofClaims = ProofClaims{}

		if v, ok := proof["domain"]; ok {
			proofClaims.Audience = v.(string) //nolint:errcheck
			proofClaims.Issuer = v.(string)   //nolint:errcheck
		}
		if v, ok := proof["challenge"]; ok {
			proofClaims.Nonce = v.(string) //nolint:errcheck
		}
		if v, ok := proof["created"]; ok {
			t, timeErr := time.Parse(time.RFC3339, v.(string)) //nolint:errcheck
			if timeErr != nil {
				return "", "",
					oidc4cierr.NewInvalidCredentialRequestError(timeErr).WithErrorPrefix("parse created")
			}
			proofClaims.IssuedAt = lo.ToPtr(t.Unix())
		}
	}

	did, err := c.validateProofClaims(clientID, &proofClaims, proofHeaders, session)
	if err != nil {
		return "", "", err
	}

	return did, proofClaims.Audience, nil
}

func (c *Controller) getDataIntegrityVerifier() (*dataintegrity.Verifier, error) {
	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: c.vdr,
	}, eddsa2022.NewVerifierInitializer(&eddsa2022.VerifierInitializerOptions{
		LDDocumentLoader: c.documentLoader,
	}), ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: c.documentLoader,
	}))

	if err != nil {
		return nil, fmt.Errorf("new verifier: %w", err)
	}

	return verifier, nil
}

// OidcCredential handles OIDC credential request (POST /oidc/credential).
//
// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7
//
// Success response: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.3
//
// Error responses: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.3.1
func (c *Controller) OidcCredential(e echo.Context) error { //nolint:funlen
	req := e.Request()

	ctx, span := c.tracer.Start(req.Context(), "OidcCredential")
	defer span.End()

	var credentialReq CredentialRequest

	if err := e.Bind(&credentialReq); err != nil {
		return oidc4cierr.NewInvalidCredentialRequestError(err).UsePublicAPIResponse()
	}

	if err := validateCredentialRequest(e, &credentialReq); err != nil {
		return err.UsePublicAPIResponse()
	}

	span.SetAttributes(attributeutil.JSON("oidc_credential_request", credentialReq))

	token := fosite.AccessTokenFromRequest(req)
	if token == "" {
		return resterr.NewFositeAccessTokenInvalidTokenErr(e, c.oauth2Provider)
	}

	_, ar, err := c.oauth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewFositeIntrospectTokenInvalidTokenErr(e, c.oauth2Provider)
	}

	session := ar.GetSession().(*fosite.DefaultSession) //nolint:errcheck

	did, aud, err := c.HandleProof(ar.GetClient().GetID(), &credentialReq, session)
	if err != nil {
		var oidc4ciErr *oidc4cierr.Error

		if !errors.As(err, &oidc4ciErr) {
			oidc4ciErr = oidc4cierr.NewInvalidCredentialRequestError(err)
		}

		return oidc4ciErr.UsePublicAPIResponse()
	}

	var credentialTypes []string

	if credentialReq.CredentialDefinition != nil {
		credentialTypes = credentialReq.CredentialDefinition.Type
	}

	prepareCredentialReq := issuer.PrepareCredentialJSONRequestBody{
		TxId:          session.Extra[txIDKey].(string), //nolint:errcheck
		Did:           &did,
		Types:         credentialTypes,
		Format:        credentialReq.Format,
		AudienceClaim: aud,
		HashedToken:   hashToken(token),
	}

	if credentialReq.CredentialResponseEncryption != nil {
		prepareCredentialReq.RequestedCredentialResponseEncryption = &issuer.RequestedCredentialResponseEncryption{
			Alg: credentialReq.CredentialResponseEncryption.Alg,
			Enc: credentialReq.CredentialResponseEncryption.Enc,
		}
	}

	resp, err := c.issuerInteractionClient.PrepareCredential(ctx, prepareCredentialReq)
	if err != nil {
		return oidc4cierr.NewInvalidCredentialRequestError(err).
			WithErrorPrefix("prepare credential").
			UsePublicAPIResponse()
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		finalErr := oidc4cierr.ParseCredentialEndpointErrorResponse(resp.Body)

		return finalErr.UsePublicAPIResponse()
	}

	var prepareCredentialResult issuer.PrepareCredentialResult

	if err = json.NewDecoder(resp.Body).Decode(&prepareCredentialResult); err != nil {
		return oidc4cierr.NewInvalidCredentialRequestError(err).
			WithErrorPrefix("decode prepare credential result").
			UsePublicAPIResponse()
	}

	nonce := mustGenerateNonce()

	session.Extra[cNonceKey] = nonce
	session.Extra[cNonceExpiresAtKey] = time.Now().Add(cNonceTTL).Unix()

	credentialResp := &CredentialResponse{
		Credential:      prepareCredentialResult.Credential,
		CNonce:          lo.ToPtr(nonce),
		CNonceExpiresIn: lo.ToPtr(int(cNonceTTL.Seconds())),
		NotificationId:  prepareCredentialResult.NotificationId,
		Credentials:     prepareCredentialResult.Credentials,
	}

	if credentialReq.CredentialResponseEncryption != nil {
		var encryptedResponse string

		if encryptedResponse, err = c.encryptCredentialResponse(
			credentialResp,
			credentialReq.CredentialResponseEncryption,
		); err != nil {
			return oidc4cierr.NewInvalidCredentialRequestError(err).
				WithErrorPrefix("encrypt credential response").
				UsePublicAPIResponse()
		}

		e.Response().Header().Set("Content-Type", "application/jwt")
		e.Response().WriteHeader(http.StatusOK)

		if _, err = e.Response().Write([]byte(encryptedResponse)); err != nil {
			return oidc4cierr.NewInvalidCredentialRequestError(err).
				WithErrorPrefix("write response").
				UsePublicAPIResponse()
		}

		return nil
	}

	return apiUtil.WriteOutput(e)(credentialResp, nil)
}

// OidcBatchCredential handles OIDC batch credential request (POST /oidc/batch_credential).
//
// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-8
//
// Success response: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-8.2
//
// Error responses: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-8.3
func (c *Controller) OidcBatchCredential(e echo.Context) error { //nolint:funlen,gocognit
	req := e.Request()

	ctx, span := c.tracer.Start(req.Context(), "OidcBatchCredential")
	defer span.End()

	var credentialReq BatchCredentialRequest

	if err := e.Bind(&credentialReq); err != nil {
		return oidc4cierr.NewInvalidCredentialRequestError(err).UsePublicAPIResponse()
	}

	for _, cr := range credentialReq.CredentialRequests {
		credentialRequest := cr
		if err := validateCredentialRequest(e, &credentialRequest); err != nil {
			return err.UsePublicAPIResponse()
		}
	}

	span.SetAttributes(attributeutil.JSON("oidc_batch_credential_request", credentialReq))

	token := fosite.AccessTokenFromRequest(req)
	if token == "" {
		return resterr.NewFositeAccessTokenInvalidTokenErr(e, c.oauth2Provider)
	}

	_, ar, err := c.oauth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewFositeIntrospectTokenInvalidTokenErr(e, c.oauth2Provider)
	}

	session := ar.GetSession().(*fosite.DefaultSession) //nolint:errcheck

	prepareCredentialReq := issuer.PrepareBatchCredential{
		TxId:               session.Extra[txIDKey].(string), //nolint:errcheck,
		HashedToken:        hashToken(token),
		CredentialRequests: make([]issuer.PrepareCredentialBase, 0, len(credentialReq.CredentialRequests)),
	}

	for _, cr := range credentialReq.CredentialRequests {
		credentialRequest := cr
		did, aud, handleProofErr := c.HandleProof(ar.GetClient().GetID(), &credentialRequest, session)
		if handleProofErr != nil {
			var oidc4ciErr *oidc4cierr.Error

			if !errors.As(handleProofErr, &oidc4ciErr) {
				oidc4ciErr = oidc4cierr.NewInvalidCredentialRequestError(handleProofErr)
			}

			return oidc4ciErr.UsePublicAPIResponse()
		}

		var credentialTypes []string

		if credentialRequest.CredentialDefinition != nil {
			credentialTypes = credentialRequest.CredentialDefinition.Type
		}

		prepareCredential := issuer.PrepareCredentialBase{
			AudienceClaim:                         aud,
			Did:                                   &did,
			Format:                                credentialRequest.Format,
			Types:                                 credentialTypes,
			RequestedCredentialResponseEncryption: nil,
		}

		if cr.CredentialResponseEncryption != nil {
			prepareCredential.RequestedCredentialResponseEncryption = &issuer.RequestedCredentialResponseEncryption{
				Alg: credentialRequest.CredentialResponseEncryption.Alg,
				Enc: credentialRequest.CredentialResponseEncryption.Enc,
			}
		}

		prepareCredentialReq.CredentialRequests = append(prepareCredentialReq.CredentialRequests, prepareCredential)
	}

	resp, err := c.issuerInteractionClient.PrepareBatchCredential(ctx, prepareCredentialReq)
	if err != nil {
		return oidc4cierr.NewInvalidCredentialRequestError(err).
			WithErrorPrefix("prepare batch credential").
			UsePublicAPIResponse()
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		finalErr := oidc4cierr.ParseCredentialEndpointErrorResponse(resp.Body)

		return finalErr.UsePublicAPIResponse()
	}

	var preparedCredentials []issuer.PrepareCredentialResult

	if err = json.NewDecoder(resp.Body).Decode(&preparedCredentials); err != nil {
		return oidc4cierr.NewInvalidCredentialRequestError(err).
			WithErrorPrefix("decode prepare credential result").
			UsePublicAPIResponse()
	}

	// A successful Batch Credential Response MUST contain all the requested Credentials.
	if len(preparedCredentials) != len(credentialReq.CredentialRequests) {
		mismatchErr := fmt.Errorf(
			"credential amount mismatch, requested %d, got %d",
			len(credentialReq.CredentialRequests),
			len(preparedCredentials))

		return oidc4cierr.NewInvalidCredentialRequestError(mismatchErr).
			UsePublicAPIResponse()
	}

	nonce := mustGenerateNonce()

	session.Extra[cNonceKey] = nonce
	session.Extra[cNonceExpiresAtKey] = time.Now().Add(cNonceTTL).Unix()

	credentialResponseBatch := BatchCredentialResponse{
		CNonce:              lo.ToPtr(nonce),
		CNonceExpiresIn:     lo.ToPtr(int(cNonceTTL.Seconds())),
		CredentialResponses: make([]any, 0, len(preparedCredentials)),
	}

	for index, credentialData := range preparedCredentials {
		credentialResponse := CredentialResponseBatchCredential{
			Credential:     credentialData.Credential,
			NotificationId: &preparedCredentials[index].NotificationId,
			TransactionId:  nil, // Deferred Issuance transaction is not supported for now.
		}

		// Each element within the array matches the corresponding Credential Request
		// object by array index in the credential_requests parameter of the Batch Credential Request.
		correspondingRequestedCredential := credentialReq.CredentialRequests[index]

		if correspondingRequestedCredential.CredentialResponseEncryption != nil {
			var encryptedResponse string

			if encryptedResponse, err = c.encryptCredentialResponse(
				credentialResponse,
				correspondingRequestedCredential.CredentialResponseEncryption,
			); err != nil {
				return oidc4cierr.NewInvalidCredentialRequestError(err).
					WithErrorPrefix("encrypt batch credential response").
					UsePublicAPIResponse()
			}

			credentialResponseBatch.CredentialResponses = append(
				credentialResponseBatch.CredentialResponses, encryptedResponse)

			continue
		}

		credentialResponseBatch.CredentialResponses = append(
			credentialResponseBatch.CredentialResponses, credentialResponse)
	}

	return apiUtil.WriteOutput(e)(credentialResponseBatch, nil)
}

func validateCredentialRequest(_ echo.Context, req *CredentialRequest) *oidc4cierr.Error {
	_, err := common.ValidateVCFormat(common.VCFormat(lo.FromPtr(req.Format)))
	if err != nil {
		return oidc4cierr.NewUnsupportedCredentialFormatError(err)
	}

	if req.Proof == nil {
		return oidc4cierr.NewInvalidProofError(errors.New("missing proof type"))
	}

	switch req.Proof.ProofType {
	case "jwt":
		if lo.FromPtr(req.Proof.Jwt) == "" {
			return oidc4cierr.NewInvalidProofError(errors.New("invalid proof type"))
		}
	case "cwt":
		if lo.FromPtr(req.Proof.Cwt) == "" {
			return oidc4cierr.NewInvalidProofError(errors.New("missing cwt proof"))
		}
	case "ldp_vp":
		if req.Proof.LdpVp == nil {
			return oidc4cierr.NewInvalidProofError(errors.New("missing ldp_vp proof"))
		}
	default:
		return oidc4cierr.NewInvalidProofError(errors.New("invalid proof type"))
	}

	return nil
}

func (c *Controller) encryptCredentialResponse(
	resp interface{},
	enc *CredentialResponseEncryption,
) (string, error) {
	var jwk gojose.JSONWebKey

	if err := json.Unmarshal([]byte(enc.Jwk), &jwk); err != nil {
		return "", fmt.Errorf("unmarshal jwk: %w", err)
	}

	encrypter, err := c.jweEncrypterCreator(jwk, gojose.KeyAlgorithm(enc.Alg), gojose.ContentEncryption(enc.Enc))
	if err != nil {
		return "", fmt.Errorf("create encrypter: %w", err)
	}

	b, err := json.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("marshal credential response: %w", err)
	}

	encrypted, err := encrypter.Encrypt(b)
	if err != nil {
		return "", fmt.Errorf("encrypt credential response: %w", err)
	}

	jwe, err := encrypted.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize credential response: %w", err)
	}

	return jwe, nil
}

//nolint:gocognit
func (c *Controller) validateProofClaims(
	clientID string,
	claims *ProofClaims,
	headers ProofHeaders,
	session *fosite.DefaultSession,
) (string, *oidc4cierr.Error) {
	if nonceExp, ok := session.Extra[cNonceExpiresAtKey].(int64); ok && nonceExp < time.Now().Unix() {
		return "", oidc4cierr.NewInvalidProofError(errors.New("nonce expired"))
	}

	if nonceExp, ok := session.Extra[cNonceExpiresAtKey].(float64); ok && int64(nonceExp) < time.Now().Unix() {
		return "", oidc4cierr.NewInvalidProofError(errors.New("nonce expired"))
	}

	if headers.ProofType != proofTypeLDPVP {
		if isPreAuthFlow, ok := session.Extra[preAuthKey].(bool); !ok || (!isPreAuthFlow && claims.Issuer != clientID) {
			return "", oidc4cierr.NewInvalidProofError(errors.New("invalid client_id"))
		}
	}

	if claims.IssuedAt == nil {
		return "", oidc4cierr.NewInvalidProofError(errors.New("missing iat"))
	}

	if headers.ProofType != proofTypeLDPVP { // ldp_vp checked in parse presentation
		if nonce := session.Extra[cNonceKey].(string); claims.Nonce != nonce { //nolint:errcheck
			return "", oidc4cierr.NewInvalidProofError(errors.New("invalid nonce"))
		}
	}

	switch headers.ProofType {
	case proofTypeJWT:
		if headers.Type != jwtProofTypHeader {
			return "", oidc4cierr.NewInvalidProofError(errors.New("invalid typ"))
		}
	case proofTypeCWT:
		if headers.Type != cwtProofTypHeader {
			return "", oidc4cierr.NewInvalidProofError(errors.New("invalid typ"))
		}
	}

	if headers.KeyID == "" {
		return "", oidc4cierr.NewInvalidProofError(errors.New("invalid kid"))
	}

	targetDID := strings.Split(headers.KeyID, "#")[0]

	if headers.ProofType == proofTypeCWT { // for CWT extract from claim per spec
		targetDID = claims.Issuer
	}

	logger.Warn("proofType: " + headers.ProofType)
	logger.Warn("targetDID: " + targetDID)
	logger.Warn("claims: " + spew.Sdump(claims))

	return targetDID, nil
}

// oidcPreAuthorizedCode handles pre-authorized code token request.
func (c *Controller) oidcPreAuthorizedCode(
	ctx context.Context,
	preAuthorizedCode string,
	txCode string,
	clientID string,
	clientAssertionType string,
	clientAssertion string,
) (*issuer.ValidatePreAuthorizedCodeResponse, *rfc6749.Error) {
	resp, err := c.issuerInteractionClient.ValidatePreAuthorizedCodeRequest(ctx,
		issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
			PreAuthorizedCode:   preAuthorizedCode,
			UserPin:             lo.ToPtr(txCode),
			ClientId:            lo.ToPtr(clientID),
			ClientAssertionType: lo.ToPtr(clientAssertionType),
			ClientAssertion:     lo.ToPtr(clientAssertion),
		})
	if err != nil {
		return nil, rfc6749.NewInvalidRequestError(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, rfc6749.Parse(resp.Body).
			WithErrorPrefix("validate pre-authorized code request")
	}

	var validateResponse issuer.ValidatePreAuthorizedCodeResponse
	if err = json.NewDecoder(resp.Body).Decode(&validateResponse); err != nil {
		return nil, rfc6749.NewInvalidRequestError(err).
			WithErrorPrefix("decode validate PreAuthorized code response")
	}

	return &validateResponse, nil
}

// OidcRegisterClient registers dynamically an OAuth 2.0 client with the VCS authorization server.
//
// Success response: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
//
// Error responses: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
//
//nolint:funlen,gocognit
func (c *Controller) OidcRegisterClient(e echo.Context, profileID string, profileVersion string) error {
	req := e.Request()

	ctx, span := c.tracer.Start(req.Context(), "OidcRegisterClient")
	defer span.End()

	span.SetAttributes(attribute.String("profile_id", profileID))
	span.SetAttributes(attribute.String("profile_version", profileVersion))

	var body RegisterOAuthClientRequest

	if err := e.Bind(&body); err != nil {
		return rfc7591.NewInvalidClientMetadataError(err).
			WithErrorPrefix("decode reqeust").
			UsePublicAPIResponse()
	}

	profile, err := c.profileService.GetProfile(profileID, profileVersion)
	if err != nil {
		return rfc7591.NewInvalidClientMetadataError(err).
			WithErrorPrefix("get profile").
			WithOperation("GetProfile").
			WithComponent(resterr.IssuerProfileSvcComponent).
			UsePublicAPIResponse()
	}

	if profile.OIDCConfig == nil || !profile.OIDCConfig.EnableDynamicClientRegistration {
		return rfc7591.NewInvalidClientMetadataError(fmt.Errorf("dynamic client registration not supported")).
			UsePublicAPIResponse()
	}

	data := &clientmanager.ClientMetadata{
		Name:                    lo.FromPtr(body.ClientName),
		URI:                     lo.FromPtr(body.ClientUri),
		RedirectURIs:            lo.FromPtr(body.RedirectUris),
		GrantTypes:              lo.FromPtr(body.GrantTypes),
		ResponseTypes:           lo.FromPtr(body.ResponseTypes),
		Scope:                   lo.FromPtr(body.Scope),
		LogoURI:                 lo.FromPtr(body.LogoUri),
		Contacts:                lo.FromPtr(body.Contacts),
		TermsOfServiceURI:       lo.FromPtr(body.TosUri),
		PolicyURI:               lo.FromPtr(body.PolicyUri),
		JSONWebKeysURI:          lo.FromPtr(body.JwksUri),
		JSONWebKeys:             lo.FromPtr(body.Jwks),
		SoftwareID:              lo.FromPtr(body.SoftwareId),
		SoftwareVersion:         lo.FromPtr(body.SoftwareVersion),
		TokenEndpointAuthMethod: lo.FromPtr(body.TokenEndpointAuthMethod),
	}

	client, err := c.clientManager.Create(ctx, profileID, profileVersion, data)
	if err != nil {
		var rfc7591Error *rfc7591.Error
		if !errors.As(err, &rfc7591Error) {
			rfc7591Error = rfc7591.NewInvalidClientMetadataError(err)
		}

		return rfc7591Error.
			WithOperation("Create").
			WithComponent(resterr.ClientManagerComponent).
			UsePublicAPIResponse()
	}

	resp := &RegisterOAuthClientResponse{
		ClientId:                client.ID,
		ClientIdIssuedAt:        int(client.CreatedAt.Unix()),
		GrantTypes:              client.GrantTypes,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
	}

	if client.Secret != nil {
		resp.ClientSecret = lo.ToPtr(string(client.Secret))
		resp.ClientSecretExpiresAt = lo.ToPtr(int(client.SecretExpiresAt))
	}

	if client.Name != "" {
		resp.ClientName = lo.ToPtr(client.Name)
	}

	if client.URI != "" {
		resp.ClientUri = lo.ToPtr(client.URI)
	}

	if client.Contacts != nil {
		resp.Contacts = lo.ToPtr(client.Contacts)
	}

	if client.JSONWebKeys != nil {
		if resp.Jwks, err = jwksToMap(client.JSONWebKeys); err != nil {
			return fmt.Errorf("convert jwks to map: %w", err)
		}
	}

	if client.JSONWebKeysURI != "" {
		resp.JwksUri = lo.ToPtr(client.JSONWebKeysURI)
	}

	if client.LogoURI != "" {
		resp.LogoUri = lo.ToPtr(client.LogoURI)
	}

	if client.PolicyURI != "" {
		resp.PolicyUri = lo.ToPtr(client.PolicyURI)
	}

	if client.RedirectURIs != nil {
		resp.RedirectUris = lo.ToPtr(client.RedirectURIs)
	}

	if client.ResponseTypes != nil {
		resp.ResponseTypes = lo.ToPtr(client.ResponseTypes)
	}

	if len(client.Scopes) > 0 {
		resp.Scope = lo.ToPtr(strings.Join(client.Scopes, " "))
	}

	if client.SoftwareID != "" {
		resp.SoftwareId = lo.ToPtr(client.SoftwareID)
	}

	if client.SoftwareVersion != "" {
		resp.SoftwareVersion = lo.ToPtr(client.SoftwareVersion)
	}

	if client.TermsOfServiceURI != "" {
		resp.TosUri = lo.ToPtr(client.TermsOfServiceURI)
	}

	b, err := json.Marshal(resp)
	if err != nil {
		return rfc7591.NewInvalidClientMetadataError(err).
			WithOperation("OidcRegisterClient").
			WithErrorPrefix("marshal register oauth client response").
			UsePublicAPIResponse()
	}

	return e.JSONBlob(http.StatusCreated, b)
}

func jwksToMap(jwks *gojose.JSONWebKeySet) (*map[string]interface{}, error) {
	b, err := json.Marshal(jwks)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}

	if err = json.Unmarshal(b, &m); err != nil {
		return nil, err
	}

	return &m, nil
}

func hashToken(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}
