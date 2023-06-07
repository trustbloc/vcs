/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package oidc4ci_test . StateStore,OAuth2Provider,IssuerInteractionClient,HTTPClient

package oidc4ci

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/samber/lo"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/valyala/fastjson"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	sessionOpStateKey          = "opState"
	authorizationDetailsKey    = "authDetails"
	txIDKey                    = "txID"
	preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	cNonceKey                  = "cNonce"
	cNonceExpiresAtKey         = "cNonceExpiresAt"
	cNonceTTL                  = 5 * time.Minute
	cNonceSize                 = 15
)

var logger = log.New("oidc4ci")

// StateStore stores authorization request/response state.
type StateStore interface {
	SaveAuthorizeState(
		ctx context.Context,
		opState string,
		state *oidc4ci.AuthorizeState,
		params ...func(insertOptions *oidc4ci.InsertOptions),
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

// Config holds configuration options for Controller.
type Config struct {
	OAuth2Provider          OAuth2Provider
	StateStore              StateStore
	HTTPClient              HTTPClient
	IssuerInteractionClient IssuerInteractionClient
	JWTVerifier             jose.SignatureVerifier
	Tracer                  trace.Tracer
	IssuerVCSPublicHost     string
	ExternalHostURL         string
}

// Controller for OIDC credential issuance API.
type Controller struct {
	oauth2Provider          OAuth2Provider
	stateStore              StateStore
	httpClient              HTTPClient
	issuerInteractionClient IssuerInteractionClient
	jwtVerifier             jose.SignatureVerifier
	tracer                  trace.Tracer
	issuerVCSPublicHost     string
	internalHostURL         string
}

// NewController creates a new Controller instance.
func NewController(config *Config) *Controller {
	return &Controller{
		oauth2Provider:          config.OAuth2Provider,
		stateStore:              config.StateStore,
		httpClient:              config.HTTPClient,
		issuerInteractionClient: config.IssuerInteractionClient,
		jwtVerifier:             config.JWTVerifier,
		tracer:                  config.Tracer,
		issuerVCSPublicHost:     config.IssuerVCSPublicHost,
		internalHostURL:         config.ExternalHostURL,
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
				Types:     authorizationDetails.Types,
				Format:    lo.ToPtr(string(authorizationDetails.Format)),
				Locations: lo.ToPtr(authorizationDetails.Locations),
				Type:      authorizationDetails.Type,
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
func (c *Controller) OidcAuthorize(e echo.Context, params OidcAuthorizeParams) error { //nolint:funlen
	req := e.Request()
	ctx := req.Context()

	ar, err := c.oauth2Provider.NewAuthorizeRequest(ctx, req)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	ses := &fosite.DefaultSession{
		Extra: map[string]interface{}{
			sessionOpStateKey:       params.IssuerState,
			authorizationDetailsKey: lo.FromPtr(params.AuthorizationDetails),
		},
	}

	var (
		credentialType []string
		vcFormat       *string
	)

	scope := []string(ar.GetRequestedScopes())

	if params.AuthorizationDetails != nil {
		var authorizationDetails common.AuthorizationDetails

		if err = json.Unmarshal([]byte(*params.AuthorizationDetails), &authorizationDetails); err != nil {
			return resterr.NewValidationError(resterr.InvalidValue, "authorization_details", err)
		}

		if _, err = common.ValidateAuthorizationDetails(&authorizationDetails); err != nil {
			return err
		}

		credentialType = authorizationDetails.Types
		vcFormat = authorizationDetails.Format
	} else {
		// using scope parameter to request credential type
		// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-scope-parameter-to-re
		credentialType = scope
	}

	r, err := c.issuerInteractionClient.PrepareAuthorizationRequest(ctx,
		issuer.PrepareAuthorizationRequestJSONRequestBody{
			AuthorizationDetails: &common.AuthorizationDetails{
				Type:   "openid_credential",
				Types:  credentialType,
				Format: vcFormat,
			},
			OpState:      params.IssuerState,
			ResponseType: params.ResponseType,
			Scope:        lo.ToPtr(scope),
		},
	)
	if err != nil {
		return fmt.Errorf("prepare claim data authorization: %w", err)
	}

	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("prepare claim data authorization: status code %d, %w",
			r.StatusCode,
			parseInteractionError(r.Body),
		)
	}

	var claimDataAuth issuer.PrepareClaimDataAuthorizationResponse

	if err = json.NewDecoder(r.Body).Decode(&claimDataAuth); err != nil {
		return fmt.Errorf("decode claim data authorization response: %w", err)
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

	ar.(*fosite.AuthorizeRequest).State = params.IssuerState

	resp, err := c.oauth2Provider.NewAuthorizeResponse(ctx, ar, ses)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	if err = c.stateStore.SaveAuthorizeState(
		ctx,
		params.IssuerState,
		&oidc4ci.AuthorizeState{
			RedirectURI: ar.GetRedirectURI(),
			RespondMode: string(ar.GetResponseMode()),
			Header:      resp.GetHeader(),
			Parameters:  resp.GetParameters(),
		}); err != nil {
		return fmt.Errorf("save authorize state: %w", err)
	}

	var authCodeURL string

	if len(lo.FromPtr(claimDataAuth.PushedAuthorizationRequestEndpoint)) > 0 {
		authCodeURL, err = c.buildAuthCodeURLWithPAR(ctx,
			oauthConfig,
			*claimDataAuth.PushedAuthorizationRequestEndpoint,
			params.IssuerState,
		)
		if err != nil {
			return err
		}
	} else {
		authCodeURL = oauthConfig.AuthCodeURL(params.IssuerState)
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

	req, err := http.NewRequest(http.MethodPost, parEndpoint, strings.NewReader(v.Encode()))
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
			logger.Error("Failed to close response body", log.WithError(err))
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

	defer storeResp.Body.Close()

	if storeResp.StatusCode != http.StatusOK {
		return fmt.Errorf("store authorization code request: status code %d, %w",
			storeResp.StatusCode,
			parseInteractionError(storeResp.Body),
		)
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
func (c *Controller) OidcToken(e echo.Context) error {
	req := e.Request()

	ctx, span := c.tracer.Start(req.Context(), "OidcToken")
	defer span.End()

	params, _ := e.FormParams()
	span.SetAttributes(attributeutil.FormParams("form_params", params))

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

	isPreAuthFlow := strings.EqualFold(e.FormValue("grant_type"), preAuthorizedCodeGrantType)
	if isPreAuthFlow { //nolint:nestif
		resp, preAuthorizeErr := c.oidcPreAuthorizedCode(
			ctx,
			e.FormValue("pre-authorized_code"),
			e.FormValue("user_pin"),
		)

		if preAuthorizeErr != nil {
			return preAuthorizeErr
		}

		txID = resp.TxId
	} else {
		exchangeResp, errExchange := c.issuerInteractionClient.ExchangeAuthorizationCodeRequest(
			ctx,
			issuer.ExchangeAuthorizationCodeRequestJSONRequestBody{
				OpState: ar.GetSession().(*fosite.DefaultSession).Extra[sessionOpStateKey].(string),
			},
		)
		if errExchange != nil {
			return fmt.Errorf("exchange authorization code request: %w", errExchange)
		}

		defer exchangeResp.Body.Close()

		if exchangeResp.StatusCode != http.StatusOK {
			return fmt.Errorf("exchange authorization code request: status code %d, %w",
				exchangeResp.StatusCode,
				parseInteractionError(exchangeResp.Body),
			)
		}

		var exchangeResult issuer.ExchangeAuthorizationCodeResponse

		if err = json.NewDecoder(exchangeResp.Body).Decode(&exchangeResult); err != nil {
			return fmt.Errorf("read exchange auth code response: %w", err)
		}
		txID = exchangeResult.TxId
	}

	c.setCNonceSession(session, nonce, txID)

	responder, err := c.oauth2Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAccessError, e, c.oauth2Provider, err).WithAccessRequester(ar)
	}

	c.setCNonce(responder, nonce)

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

func (c *Controller) setCNonceSession(
	session *fosite.DefaultSession,
	nonce string,
	txID string,
) {
	session.Extra[txIDKey] = txID
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

// OidcCredential handles OIDC credential request (POST /oidc/credential).
func (c *Controller) OidcCredential(e echo.Context) error {
	req := e.Request()

	ctx, span := c.tracer.Start(req.Context(), "OidcCredential")
	defer span.End()

	var credentialRequest CredentialRequest

	if err := validateCredentialRequest(e, &credentialRequest); err != nil {
		return err
	}

	span.SetAttributes(attributeutil.JSON("oidc_credential_request", credentialRequest))

	token := fosite.AccessTokenFromRequest(req)
	if token == "" {
		return resterr.NewOIDCError("invalid_token", errors.New("missing access token"))
	}

	_, ar, err := c.oauth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewOIDCError("invalid_token", fmt.Errorf("introspect token: %w", err))
	}

	session := ar.GetSession().(*fosite.DefaultSession) //nolint:errcheck

	did, err := validateProofClaims(credentialRequest.Proof.Jwt, session, c.jwtVerifier)
	if err != nil {
		return resterr.NewOIDCError("invalid_or_missing_proof", err)
	}

	resp, err := c.issuerInteractionClient.PrepareCredential(ctx,
		issuer.PrepareCredentialJSONRequestBody{
			TxId:   session.Extra[txIDKey].(string), //nolint:errcheck
			Did:    lo.ToPtr(did),
			Types:  credentialRequest.Types,
			Format: credentialRequest.Format,
		},
	)
	if err != nil {
		return fmt.Errorf("prepare credential: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		parsedErr := parseInteractionError(resp.Body)
		finalErr := fmt.Errorf("prepare credential: status code %d, %w",
			resp.StatusCode,
			parsedErr)

		var interactionErr *interactionError

		if errors.As(parsedErr, &interactionErr) {
			switch interactionErr.Code { //nolint:exhaustive
			case resterr.OIDCCredentialFormatNotSupported:
				return resterr.NewOIDCError("unsupported_credential_format", finalErr)
			case resterr.OIDCCredentialTypeNotSupported:
				return resterr.NewOIDCError("unsupported_credential_type", finalErr)
			}
		}

		return finalErr
	}

	var result issuer.PrepareCredentialResult

	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode prepare credential result: %w", err)
	}

	nonce := mustGenerateNonce()

	session.Extra[cNonceKey] = nonce
	session.Extra[cNonceExpiresAtKey] = time.Now().Add(cNonceTTL).Unix()

	return apiUtil.WriteOutput(e)(CredentialResponse{
		Credential:      result.Credential,
		Format:          result.OidcFormat,
		CNonce:          lo.ToPtr(nonce),
		CNonceExpiresIn: lo.ToPtr(int(cNonceTTL.Seconds())),
	}, nil)
}

func validateCredentialRequest(e echo.Context, req *CredentialRequest) error {
	if err := e.Bind(req); err != nil {
		return err
	}

	_, err := common.ValidateVCFormat(common.VCFormat(lo.FromPtr(req.Format)))
	if err != nil {
		return resterr.NewOIDCError("invalid_request", err)
	}

	if req.Proof == nil {
		return resterr.NewOIDCError("invalid_request", errors.New("missing proof type"))
	}

	if req.Proof.ProofType != "jwt" || req.Proof.Jwt == "" {
		return resterr.NewOIDCError("invalid_request", errors.New("invalid proof type"))
	}

	return nil
}

func validateProofClaims(
	rawJwt string,
	session *fosite.DefaultSession,
	verifier jose.SignatureVerifier,
) (string, error) {
	jws, rawClaims, err := jwt.Parse(rawJwt,
		jwt.WithSignatureVerifier(verifier),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return "", resterr.NewOIDCError("invalid_or_missing_proof", fmt.Errorf("parse jwt: %w", err))
	}

	if nonceExp, ok := session.Extra[cNonceExpiresAtKey].(int64); ok && nonceExp < time.Now().Unix() {
		return "", resterr.NewOIDCError("invalid_or_missing_proof", errors.New("nonce expired"))
	}

	if nonceExp, ok := session.Extra[cNonceExpiresAtKey].(float64); ok && int64(nonceExp) < time.Now().Unix() {
		return "", resterr.NewOIDCError("invalid_or_missing_proof", errors.New("nonce expired"))
	}

	if nonce := session.Extra[cNonceKey].(string); fastjson.GetString(rawClaims, "nonce") != nonce { //nolint:errcheck
		return "", resterr.NewOIDCError("invalid_or_missing_proof", errors.New("invalid nonce"))
	}

	keyID, _ := jws.Headers.KeyID()
	return strings.Split(keyID, "#")[0], nil
}

// oidcPreAuthorizedCode handles pre-authorized code token request.
func (c *Controller) oidcPreAuthorizedCode(
	ctx context.Context,
	preAuthorizedCode string,
	userPin string,
) (*issuer.ValidatePreAuthorizedCodeResponse, error) {
	resp, err := c.issuerInteractionClient.ValidatePreAuthorizedCodeRequest(ctx,
		issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
			PreAuthorizedCode: preAuthorizedCode,
			UserPin:           lo.ToPtr(userPin),
		})
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		parsedErr := parseInteractionError(resp.Body)

		finalErr := fmt.Errorf("validate pre-authorized code request: status code %d, %w",
			resp.StatusCode,
			parsedErr,
		)

		var interactionErr *interactionError

		if ok := errors.As(parsedErr, &interactionErr); ok {
			switch interactionErr.Code { //nolint:exhaustive
			case resterr.OIDCPreAuthorizeExpectPin:
				fallthrough
			case resterr.OIDCPreAuthorizeDoesNotExpectPin:
				return nil, resterr.NewOIDCError("invalid_request", finalErr)

			case resterr.OIDCTxNotFound:
				fallthrough
			case resterr.OIDCPreAuthorizeInvalidPin:
				return nil, resterr.NewOIDCError("invalid_grant", finalErr)
			}
		}

		return nil, finalErr
	}

	var validateResponse issuer.ValidatePreAuthorizedCodeResponse
	if err = json.NewDecoder(resp.Body).Decode(&validateResponse); err != nil {
		return nil, err
	}

	return &validateResponse, nil
}

// OidcRegisterDynamicClient handles OIDC Dynamic Client Registration (POST /oidc/register).
func (c *Controller) OidcRegisterDynamicClient(e echo.Context) error {
	req := e.Request()
	ctx := req.Context()

	_, span := c.tracer.Start(ctx, "OidcRegisterDynamicClient")
	defer span.End()

	var registrationReq ClientRegistrationRequest

	if err := e.Bind(&registrationReq); err != nil {
		return fmt.Errorf("bind client registration request: %w", err)
	}

	resp, err := c.issuerInteractionClient.RegisterOauthClient(ctx,
		issuer.RegisterOAuthClientRequest{
			Data: issuer.ClientRegistrationData{
				ClientName:              lo.FromPtr(registrationReq.ClientName),
				ClientUri:               lo.FromPtr(registrationReq.ClientUri),
				GrantTypes:              registrationReq.GrantTypes,
				RedirectUris:            lo.FromPtr(registrationReq.RedirectUris),
				ResponseTypes:           lo.FromPtr(registrationReq.ResponseTypes),
				Scope:                   lo.FromPtr(registrationReq.Scope),
				TokenEndpointAuthMethod: lo.FromPtr(registrationReq.TokenEndpointAuthMethod),
			},
			OpState: registrationReq.IssuerState,
		},
	)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register oauth client: status code %d, %w",
			resp.StatusCode,
			parseInteractionError(resp.Body),
		)
	}

	var registrationResp ClientRegistrationResponse

	if err = json.NewDecoder(resp.Body).Decode(&registrationResp); err != nil {
		return fmt.Errorf("decode client registration response: %w", err)
	}

	b, err := json.Marshal(registrationResp)
	if err != nil {
		return fmt.Errorf("marshal client registration response: %w", err)
	}

	return e.JSONBlob(http.StatusCreated, b)
}

type interactionError struct { // in fact its CustomError
	Code           resterr.ErrorCode `json:"code"`
	Component      string            `json:"component,omitempty"`
	Operation      string            `json:"operation,omitempty"`
	IncorrectValue string            `json:"incorrectValue,omitempty"`
	Message        string            `json:"message,omitempty"`
}

func (e *interactionError) Error() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("code: %s", e.Code))

	if e.Component != "" {
		b.WriteString(fmt.Sprintf("; component: %s", e.Component))
	}

	if e.Operation != "" {
		b.WriteString(fmt.Sprintf("; operation: %s", e.Operation))
	}

	if e.IncorrectValue != "" {
		b.WriteString(fmt.Sprintf("; incorrect value: %s", e.IncorrectValue))
	}

	if e.Message != "" {
		b.WriteString(fmt.Sprintf("; message: %s", e.Message))
	}

	return b.String()
}

func parseInteractionError(reader io.Reader) error {
	b, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var e interactionError

	if err = json.Unmarshal(b, &e); err != nil {
		return errors.New(string(b))
	}

	return &e
}
