/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package oidc4vc_test . StateStore,OAuth2Provider,IssuerInteractionClient,HTTPClient,OAuth2Client

package oidc4vc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/samber/lo"
	"golang.org/x/oauth2"

	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4vcstatestore"
)

const (
	sessionOpStateKey          = "opState"
	authorizationDetailsKey    = "authDetails"
	preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	authorizeEndpoint          = "/oidc/authorize"
	tokenEndpoint              = "/oidc/token"
	tokenType                  = "bearer"
)

// StateStore stores authorization request/response state.
type StateStore interface {
	SaveAuthorizeState(
		ctx context.Context,
		opState string,
		state *oidc4vcstatestore.AuthorizeState,
		params ...func(insertOptions *oidc4vc.InsertOptions),
	) error

	GetAuthorizeState(
		ctx context.Context,
		opState string,
	) (*oidc4vcstatestore.AuthorizeState, error)
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type OAuth2Client interface {
	GeneratePKCE() (verifier string, challenge string, method string, err error)
	AuthCodeURL(_ context.Context, cfg oauth2.Config, state string, opts ...oauth2.AuthCodeOption) string
	Exchange(
		ctx context.Context,
		cfg oauth2.Config,
		code string,
		client *http.Client,
		opts ...oauth2.AuthCodeOption,
	) (*oauth2.Token, error)
}

// OAuth2Provider provides functionality for OAuth2 handlers.
type OAuth2Provider fosite.OAuth2Provider

// IssuerInteractionClient defines API client for interaction with issuer private API.
type IssuerInteractionClient issuer.ClientInterface

// Config holds configuration options for Controller.
type Config struct {
	OAuth2Provider          OAuth2Provider
	StateStore              StateStore
	IssuerInteractionClient IssuerInteractionClient
	IssuerVCSPublicHost     string
	OAuth2Client            OAuth2Client
	PreAuthorizeClient      HTTPClient
	DefaultHTTPClient       *http.Client
}

// Controller for OIDC4VC issuance API.
type Controller struct {
	oauth2Provider          OAuth2Provider
	stateStore              StateStore
	issuerInteractionClient IssuerInteractionClient
	issuerVCSPublicHost     string
	oAuth2Client            OAuth2Client
	preAuthorizeClient      HTTPClient
	defaultHTTPClient       *http.Client
}

// NewController creates a new Controller instance.
func NewController(config *Config) *Controller {
	return &Controller{
		oauth2Provider:          config.OAuth2Provider,
		stateStore:              config.StateStore,
		issuerInteractionClient: config.IssuerInteractionClient,
		issuerVCSPublicHost:     config.IssuerVCSPublicHost,
		oAuth2Client:            config.OAuth2Client,
		preAuthorizeClient:      config.PreAuthorizeClient,
		defaultHTTPClient:       config.DefaultHTTPClient,
	}
}

// OidcPushedAuthorizationRequest handles OIDC pushed authorization request (POST /oidc/par).
func (c *Controller) OidcPushedAuthorizationRequest(e echo.Context) error {
	req := e.Request()
	ctx := req.Context()

	ar, err := c.oauth2Provider.NewPushedAuthorizeRequest(ctx, req)
	if err != nil {
		return resterr.NewFositeError(resterr.FositePARError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	var par PushedAuthorizationRequest

	if err = e.Bind(&par); err != nil {
		return resterr.NewFositeError(resterr.FositePARError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	var ad common.AuthorizationDetails

	if err = json.Unmarshal([]byte(par.AuthorizationDetails), &ad); err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "authorization_details", err)
	}

	authorizationDetails, err := common.ValidateAuthorizationDetails(&ad)
	if err != nil {
		return err
	}

	r, err := c.issuerInteractionClient.PushAuthorizationDetails(ctx,
		issuer.PushAuthorizationDetailsJSONRequestBody{
			AuthorizationDetails: common.AuthorizationDetails{
				CredentialType: authorizationDetails.CredentialType,
				Format:         lo.ToPtr(string(authorizationDetails.Format)),
				Locations:      lo.ToPtr(authorizationDetails.Locations),
				Type:           authorizationDetails.Type,
			},
			OpState: par.OpState,
		},
	)
	if err != nil {
		return fmt.Errorf("push authorization details: %w", err)
	}

	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("push authorization details: status code %d", r.StatusCode)
	}

	resp, err := c.oauth2Provider.NewPushedAuthorizeResponse(ctx, ar, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewFositeError(resterr.FositePARError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	c.oauth2Provider.WritePushedAuthorizeResponse(ctx, e.Response().Writer, ar, resp)

	return nil
}

// OidcAuthorize handles OIDC authorization request (GET /oidc/authorize).
func (c *Controller) OidcAuthorize(e echo.Context, params OidcAuthorizeParams) error {
	req := e.Request()
	ctx := req.Context()

	ar, err := c.oauth2Provider.NewAuthorizeRequest(ctx, req)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	ses := &fosite.DefaultSession{
		Extra: map[string]interface{}{
			sessionOpStateKey:       params.OpState,
			authorizationDetailsKey: lo.FromPtr(params.AuthorizationDetails),
		},
	}

	if lo.FromPtr(params.AuthorizationDetails) == preAuthorizedCodeGrantType { // pre-authorization flow
		resp, err2 := c.oauth2Provider.NewAuthorizeResponse(ctx, ar, ses)
		if err2 != nil {
			return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err2).WithAuthorizeRequester(ar)
		}

		c.oauth2Provider.WriteAuthorizeResponse(ctx, e.Response().Writer, ar, resp)
		return nil
	}

	var scope []string

	for _, s := range ar.GetRequestedScopes() {
		scope = append(scope, s)
	}

	r, err := c.issuerInteractionClient.PrepareAuthorizationRequest(ctx,
		issuer.PrepareAuthorizationRequestJSONRequestBody{
			AuthorizationDetails: &common.AuthorizationDetails{
				Type:           "openid_credential",
				CredentialType: "PermanentResidentCard", // TODO: Set from the request.
				Format:         lo.ToPtr("ldp_vc"),
			},
			OpState:      params.OpState,
			ResponseType: params.ResponseType,
			Scope:        lo.ToPtr(scope),
		},
	)
	if err != nil {
		return fmt.Errorf("prepare claim data authorization: %w", err)
	}

	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("prepare claim data authorization: status code %d", r.StatusCode)
	}

	var claimDataAuth issuer.PrepareClaimDataAuthorizationResponse

	if err = json.NewDecoder(r.Body).Decode(&claimDataAuth); err != nil {
		return fmt.Errorf("decode claim data authorization response: %w", err)
	}

	// TODO: Perform PAR request to issuer's OIDC provider if claimDataAuth.PushedAuthorizationRequestEndpoint != nil.

	oauthConfig := &oauth2.Config{
		ClientID:     claimDataAuth.AuthorizationRequest.ClientId,
		ClientSecret: claimDataAuth.AuthorizationRequest.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   claimDataAuth.AuthorizationEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: c.issuerVCSPublicHost + "/oidc/redirect",
		Scopes:      claimDataAuth.AuthorizationRequest.Scope,
	}

	ar.(*fosite.AuthorizeRequest).State = params.OpState

	resp, err := c.oauth2Provider.NewAuthorizeResponse(ctx, ar, ses)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	if err = c.stateStore.SaveAuthorizeState(
		ctx,
		params.OpState,
		&oidc4vcstatestore.AuthorizeState{
			RedirectURI: ar.GetRedirectURI(),
			RespondMode: string(ar.GetResponseMode()),
			Header:      resp.GetHeader(),
			Parameters:  resp.GetParameters(),
		}); err != nil {
		return fmt.Errorf("save authorize state: %w", err)
	}

	return e.Redirect(http.StatusSeeOther, oauthConfig.AuthCodeURL(params.OpState))
}

// OidcRedirect handles OIDC redirect (GET /oidc/redirect).
func (c *Controller) OidcRedirect(e echo.Context, params OidcRedirectParams) error {
	req := e.Request()
	ctx := req.Context()

	resp, err := c.stateStore.GetAuthorizeState(ctx, params.State)
	if err != nil {
		return apiUtil.WriteOutput(e)(nil, err)
	}

	storeResp, storeErr := c.issuerInteractionClient.StoreAuthorizationCodeRequest(ctx,
		issuer.StoreAuthorizationCodeRequestJSONRequestBody{
			Code:    params.Code,
			OpState: params.State,
		})
	if storeErr != nil {
		return storeErr
	}
	_ = storeResp.Body.Close()

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
func (c *Controller) OidcToken(e echo.Context) error {
	req := e.Request()
	ctx := req.Context()

	ar, err := c.oauth2Provider.NewAccessRequest(ctx, req, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAccessError, e, c.oauth2Provider, err).WithAccessRequester(ar)
	}

	isPreAuthFlow := ar.GetSession().(*fosite.DefaultSession).Extra[authorizationDetailsKey] == preAuthorizedCodeGrantType
	if isPreAuthFlow {
		resp, err2 := c.oauth2Provider.NewAccessResponse(ctx, ar)
		if err2 != nil {
			return resterr.NewFositeError(resterr.FositeAccessError, e, c.oauth2Provider, err2).WithAccessRequester(ar)
		}

		c.oauth2Provider.WriteAccessResponse(ctx, e.Response().Writer, ar, resp)
		return nil
	}

	exchangeResp, err := c.issuerInteractionClient.ExchangeAuthorizationCodeRequest(
		ctx,
		issuer.ExchangeAuthorizationCodeRequestJSONRequestBody{
			OpState: ar.GetSession().(*fosite.DefaultSession).Extra[sessionOpStateKey].(string),
		},
	)
	if err != nil {
		return err
	}
	_ = exchangeResp.Body.Close()

	resp, err := c.oauth2Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAccessError, e, c.oauth2Provider, err).WithAccessRequester(ar)
	}

	c.oauth2Provider.WriteAccessResponse(ctx, e.Response().Writer, ar, resp)
	return nil
}

// OidcPreAuthorizedCode handles pre-authorized code token request (POST /oidc/pre-authorized-code).
func (c *Controller) OidcPreAuthorizedCode(e echo.Context) error {
	if !strings.EqualFold(e.FormValue("grant_type"), preAuthorizedCodeGrantType) {
		return fmt.Errorf("unexpected grant type. expected %v", preAuthorizedCodeGrantType)
	}

	ctx := e.Request().Context()

	resp, err := c.issuerInteractionClient.ValidatePreAuthorizedCodeRequest(ctx,
		issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
			PreAuthorizedCode: e.FormValue("pre-authorized_code"),
			UserPin:           lo.ToPtr(e.FormValue("user_pin")),
		})
	if err != nil {
		return err
	}

	var validateResponse issuer.ValidatePreAuthorizedCodeResponse
	if err = json.NewDecoder(resp.Body).Decode(&validateResponse); err != nil {
		return err
	}
	_ = resp.Body.Close()

	verifier, challenge, method, err := c.oAuth2Client.GeneratePKCE()
	if err != nil {
		return err
	}

	cfg := oauth2.Config{
		ClientID:     "pre-auth-client",
		ClientSecret: "foobar",
		RedirectURL:  c.issuerVCSPublicHost + tokenEndpoint,
		Scopes:       validateResponse.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   c.issuerVCSPublicHost + authorizeEndpoint,
			TokenURL:  c.issuerVCSPublicHost + tokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	authURL := c.oAuth2Client.AuthCodeURL(ctx,
		cfg,
		validateResponse.OpState,
		oauth2.SetAuthURLParam("authorization_details", preAuthorizedCodeGrantType),
		oauth2.SetAuthURLParam("op_state", validateResponse.OpState),
		oauth2.SetAuthURLParam("code_challenge_method", method),
		oauth2.SetAuthURLParam("code_challenge", challenge),
	)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return err
	}

	resp, err = c.preAuthorizeClient.Do(httpReq)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusSeeOther {
		return fmt.Errorf("unexpected status code %v, expected %v", resp.StatusCode,
			http.StatusSeeOther)
	}

	parsedURL, err := url.Parse(resp.Header.Get("location"))
	if err != nil {
		return err
	}

	token, err := c.oAuth2Client.Exchange(ctx, cfg,
		parsedURL.Query().Get("code"),
		c.defaultHTTPClient,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return err
	}

	aResponse := AccessTokenResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: lo.ToPtr(token.RefreshToken),
		TokenType:    tokenType,
	}
	if token.Expiry.Unix() > 0 {
		aResponse.ExpiresIn = lo.ToPtr(int(token.Expiry.Unix()))
	}

	return apiUtil.WriteOutput(e)(aResponse, nil)
}
