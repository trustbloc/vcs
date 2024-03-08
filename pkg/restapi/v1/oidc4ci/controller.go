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
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/veraison/go-cose"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/clientidscheme"
	"github.com/trustbloc/vcs/pkg/service/clientmanager"
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
	cwtProofTypHeader          = "openid4vci-proof+cwt"
	cNonceKey                  = "cNonce"
	cNonceExpiresAtKey         = "cNonceExpiresAt"
	cNonceSize                 = 15
	cNonceTTL                  = 5 * time.Minute

	invalidRequestOIDCErr = "invalid_request"
	invalidGrantOIDCErr   = "invalid_grant"
	invalidTokenOIDCErr   = "invalid_token"
	invalidClientOIDCErr  = "invalid_client"

	proofTypeCWT   = "cwt"
	proofTypeJWT   = "jwt"
	proofTypeLDPVP = "ldp_vp"
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
	Ack(
		ctx context.Context,
		req oidc4ci.AckRemote,
	) error
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

	var ad []common.AuthorizationDetails

	if err = json.Unmarshal([]byte(par.AuthorizationDetails), &ad); err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "authorization_details", err)
	}

	_, err = apiUtil.ValidateAuthorizationDetails(ad)
	if err != nil {
		return err
	}

	r, err := c.issuerInteractionClient.PushAuthorizationDetails(ctx,
		issuer.PushAuthorizationDetailsJSONRequestBody{
			AuthorizationDetails: ad,
			OpState:              par.OpState,
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
func (c *Controller) OidcAuthorize(e echo.Context, params OidcAuthorizeParams) error { //nolint:funlen,gocognit
	req := e.Request()
	ctx := req.Context()

	if lo.FromPtr(params.IssuerState) == "" {
		params.IssuerState = lo.ToPtr(uuid.NewString())
	}

	if lo.FromPtr(params.ClientIdScheme) == discoverableClientIDScheme {
		if err := c.clientIDSchemeService.Register(ctx, params.ClientId, lo.FromPtr(params.IssuerState)); err != nil {
			logger.Errorc(ctx, "Failed to register client", log.WithError(err))
			return resterr.NewSystemError(resterr.ClientIDSchemeSvcComponent, "Register", err)
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
			return resterr.NewValidationError(resterr.InvalidValue, "authorization_details", err)
		}

		if _, err = apiUtil.ValidateAuthorizationDetails(authorizationDetails); err != nil {
			return err
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

	if claimDataAuth.WalletInitiatedFlow != nil {
		ses.Extra[sessionOpStateKey] = claimDataAuth.WalletInitiatedFlow.OpState // swap op state
		params.IssuerState = &claimDataAuth.WalletInitiatedFlow.OpState
	}

	if params.State != nil {
		ar.(*fosite.AuthorizeRequest).State = *params.State
	}

	resp, err := c.oauth2Provider.NewAuthorizeResponse(ctx, ar, ses)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	if err = c.stateStore.SaveAuthorizeState(
		ctx,
		lo.FromPtr(params.IssuerState),
		&oidc4ci.AuthorizeState{
			RedirectURI:         ar.GetRedirectURI(),
			RespondMode:         string(ar.GetResponseMode()),
			Header:              resp.GetHeader(),
			Parameters:          resp.GetParameters(),
			WalletInitiatedFlow: claimDataAuth.WalletInitiatedFlow,
		}); err != nil {
		return fmt.Errorf("save authorize state: %w", err)
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
			return err
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
		return apiUtil.WriteOutput(e)(nil, err)
	}

	storeResp, storeErr := c.issuerInteractionClient.StoreAuthorizationCodeRequest(ctx,
		issuer.StoreAuthorizationCodeRequestJSONRequestBody{
			Code:                params.Code,
			OpState:             params.State,
			WalletInitiatedFlow: resp.WalletInitiatedFlow,
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
			return preAuthorizeErr
		}

		txID = resp.TxId
		authorisationDetails = resp.AuthorizationDetails
	} else {
		exchangeResp, errExchange := c.issuerInteractionClient.ExchangeAuthorizationCodeRequest(
			ctx,
			issuer.ExchangeAuthorizationCodeRequestJSONRequestBody{
				OpState:             ar.GetSession().(*fosite.DefaultSession).Extra[sessionOpStateKey].(string),
				ClientId:            lo.ToPtr(ar.GetClient().GetID()),
				ClientAssertionType: lo.ToPtr(e.FormValue("client_assertion_type")),
				ClientAssertion:     lo.ToPtr(e.FormValue("client_assertion")),
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

// OidcAcknowledgement handles OIDC acknowledgement request (POST /oidc/notification).
func (c *Controller) OidcAcknowledgement(e echo.Context) error {
	req := e.Request()

	// ctx, span := c.tracer.Start(req.Context(), "OidcAcknowledgement")
	// defer span.End()

	var body AckRequest
	if err := e.Bind(&body); err != nil {
		return err
	}

	token := fosite.AccessTokenFromRequest(req)
	if token == "" {
		return resterr.NewOIDCError(invalidTokenOIDCErr, errors.New("missing access token"))
	}

	// for now we dont need to introspect token as it can be expired.
	// todo: once new we have new spec add logic with token
	// _, _, err := c.oauth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, new(fosite.DefaultSession))
	// if err != nil {
	//	return resterr.NewOIDCError(invalidTokenOIDCErr, fmt.Errorf("introspect token: %w", err))
	// }

	var finalErr error
	for _, r := range body.Credentials {
		if err := c.ackService.Ack(req.Context(), oidc4ci.AckRemote{
			HashedToken:      hashToken(token),
			ID:               r.NotificationId,
			Event:            r.Event,
			EventDescription: lo.FromPtr(r.EventDescription),
			IssuerIdentifier: lo.FromPtr(r.IssuerIdentifier),
		}); err != nil {
			finalErr = errors.Join(finalErr, err)
		}
	}

	if finalErr != nil {
		return apiUtil.WriteOutputWithCode(http.StatusBadRequest, e)(AckErrorResponse{
			Error: finalErr.Error(),
		}, nil)
	}

	return e.NoContent(http.StatusNoContent)
}

//nolint:funlen,gocognit
func (c *Controller) HandleProof(
	clientID string,
	credentialReq *CredentialRequest,
	session *fosite.DefaultSession,
) (string, string, error) {
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
				resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), fmt.Errorf("parse jwt: %w", err))
		}

		proofHeaders.Type, _ = jws.Headers.Type()
		proofHeaders.KeyID, _ = jws.Headers.KeyID()

		if err = json.Unmarshal(rawClaims, &proofClaims); err != nil {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("invalid jwt claims"))
		}
	case proofTypeCWT:
		cwtBytes, err := hex.DecodeString(lo.FromPtr(credentialReq.Proof.Cwt))
		if err != nil {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("invalid cwt"))
		}

		cwtParsed, rawClaims, err := cwt.ParseAndCheckProof(cwtBytes, c.cwtVerifier, false)
		if err != nil {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, fmt.Errorf("parse cwt: %w", err))
		}

		if err = cbor.Unmarshal(rawClaims, &proofClaims); err != nil {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("invalid cwt claims"))
		}

		typ, ok := cwtParsed.Headers.Protected[cose.HeaderLabelContentType].(string)
		if !ok {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("invalid COSE content type"))
		}
		proofHeaders.Type = typ

		cosKeyBytes, ok := cwtParsed.Headers.Protected["COSE_Key"]
		if !ok {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("invalid COSE_KEY"))
		}

		proofHeaders.KeyID = string(cosKeyBytes.([]byte))
	case proofTypeLDPVP:
		if credentialReq.Proof.LdpVp == nil {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("missing ldp_vp"))
		}

		rawProof, err := json.Marshal(*credentialReq.Proof.LdpVp)
		if err != nil {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("invalid ldp_vp"))
		}

		ver, err := c.getDataIntegrityVerifier()
		if err != nil {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, fmt.Errorf("get data integrity verifier: %w", err))
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
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr,
				errors.New("can not parse ldp_vp as presentation"))
		}

		if len(presentation.Proofs) != 1 {
			return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, fmt.Errorf("expected 1 proof, got %d",
				len(presentation.Proofs)))
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
			t, timeErr := time.Parse(time.RFC3339, v.(string))
			if timeErr != nil {
				return "", "", resterr.NewOIDCError(invalidRequestOIDCErr, fmt.Errorf("parse created: %w", timeErr))
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
	verifySuite := ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: c.documentLoader,
	})

	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: c.vdr,
	}, verifySuite)
	if err != nil {
		return nil, fmt.Errorf("new verifier: %w", err)
	}

	return verifier, nil
}

// OidcCredential handles OIDC credential request (POST /oidc/credential).
func (c *Controller) OidcCredential(e echo.Context) error { //nolint:funlen
	req := e.Request()

	ctx, span := c.tracer.Start(req.Context(), "OidcCredential")
	defer span.End()

	var credentialReq CredentialRequest

	if err := validateCredentialRequest(e, &credentialReq); err != nil {
		return err
	}

	span.SetAttributes(attributeutil.JSON("oidc_credential_request", credentialReq))

	token := fosite.AccessTokenFromRequest(req)
	if token == "" {
		return resterr.NewOIDCError(invalidTokenOIDCErr, errors.New("missing access token"))
	}

	_, ar, err := c.oauth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewOIDCError(invalidTokenOIDCErr, fmt.Errorf("introspect token: %w", err))
	}

	session := ar.GetSession().(*fosite.DefaultSession) //nolint:errcheck

	did, aud, err := c.HandleProof(ar.GetClient().GetID(), &credentialReq, session)
	if err != nil {
		return err
	}

	prepareCredentialReq := issuer.PrepareCredentialJSONRequestBody{
		TxId:          session.Extra[txIDKey].(string), //nolint:errcheck
		Did:           &did,
		Types:         credentialReq.Types,
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
			case resterr.OIDCInvalidEncryptionParameters:
				return resterr.NewOIDCError("invalid_encryption_parameters", finalErr)
			case resterr.InvalidOrMissingProofOIDCErr:
				return resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), errors.New(interactionErr.Message))
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

	credentialResp := &CredentialResponse{
		Credential:      result.Credential,
		Format:          result.OidcFormat,
		CNonce:          lo.ToPtr(nonce),
		CNonceExpiresIn: lo.ToPtr(int(cNonceTTL.Seconds())),
		NotificationId:  result.NotificationId,
	}

	if credentialReq.CredentialResponseEncryption != nil {
		var encryptedResponse string

		if encryptedResponse, err = c.encryptCredentialResponse(
			credentialResp,
			credentialReq.CredentialResponseEncryption,
		); err != nil {
			return fmt.Errorf("encrypt credential response: %w", err)
		}

		e.Response().Header().Set("Content-Type", "application/jwt")
		e.Response().WriteHeader(http.StatusOK)

		if _, err = e.Response().Write([]byte(encryptedResponse)); err != nil {
			return err
		}

		return nil
	}

	return apiUtil.WriteOutput(e)(credentialResp, nil)
}

func validateCredentialRequest(e echo.Context, req *CredentialRequest) error {
	if err := e.Bind(req); err != nil {
		return err
	}

	_, err := common.ValidateVCFormat(common.VCFormat(lo.FromPtr(req.Format)))
	if err != nil {
		return resterr.NewOIDCError(invalidRequestOIDCErr, err)
	}

	if req.Proof == nil {
		return resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("missing proof type"))
	}

	switch req.Proof.ProofType {
	case "jwt":
		if lo.FromPtr(req.Proof.Jwt) == "" {
			return resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("invalid proof type"))
		}
	case "cwt":
		if lo.FromPtr(req.Proof.Cwt) == "" {
			return resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("missing cwt proof"))
		}
	case "ldp_vp":
		if req.Proof.LdpVp == nil {
			return resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("missing ldp_vp proof"))
		}
	default:
		return resterr.NewOIDCError(invalidRequestOIDCErr, errors.New("invalid proof type"))
	}

	return nil
}

func (c *Controller) encryptCredentialResponse(
	resp *CredentialResponse,
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
) (string, error) {
	if nonceExp, ok := session.Extra[cNonceExpiresAtKey].(int64); ok && nonceExp < time.Now().Unix() {
		return "", resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), errors.New("nonce expired"))
	}

	if nonceExp, ok := session.Extra[cNonceExpiresAtKey].(float64); ok && int64(nonceExp) < time.Now().Unix() {
		return "", resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), errors.New("nonce expired"))
	}

	if headers.ProofType != proofTypeLDPVP {
		if isPreAuthFlow, ok := session.Extra[preAuthKey].(bool); !ok || (!isPreAuthFlow && claims.Issuer != clientID) {
			return "", resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), errors.New("invalid client_id"))
		}
	}

	if claims.IssuedAt == nil {
		return "", resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), errors.New("missing iat"))
	}

	if headers.ProofType != proofTypeLDPVP { // ldp_vp checked in parse presentation
		if nonce := session.Extra[cNonceKey].(string); claims.Nonce != nonce { //nolint:errcheck
			return "", resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), errors.New("invalid nonce"))
		}
	}

	switch headers.ProofType {
	case proofTypeJWT:
		if headers.Type != jwtProofTypHeader {
			return "",
				resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), errors.New("invalid typ"))
		}
	case proofTypeCWT:
		if headers.Type != cwtProofTypHeader {
			return "",
				resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), errors.New("invalid typ"))
		}
	}

	if headers.KeyID == "" {
		return "", resterr.NewOIDCError(string(resterr.InvalidOrMissingProofOIDCErr), errors.New("invalid kid"))
	}

	return strings.Split(headers.KeyID, "#")[0], nil
}

// oidcPreAuthorizedCode handles pre-authorized code token request.
func (c *Controller) oidcPreAuthorizedCode(
	ctx context.Context,
	preAuthorizedCode string,
	txCode string,
	clientID string,
	clientAssertionType string,
	clientAssertion string,
) (*issuer.ValidatePreAuthorizedCodeResponse, error) {
	resp, err := c.issuerInteractionClient.ValidatePreAuthorizedCodeRequest(ctx,
		issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
			PreAuthorizedCode:   preAuthorizedCode,
			UserPin:             lo.ToPtr(txCode),
			ClientId:            lo.ToPtr(clientID),
			ClientAssertionType: lo.ToPtr(clientAssertionType),
			ClientAssertion:     lo.ToPtr(clientAssertion),
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
				return nil, resterr.NewOIDCError(invalidRequestOIDCErr, finalErr)

			case resterr.OIDCTxNotFound:
				fallthrough
			case resterr.OIDCPreAuthorizeInvalidPin:
				return nil, resterr.NewOIDCError(invalidGrantOIDCErr, finalErr)
			case resterr.OIDCPreAuthorizeInvalidClientID:
				return nil, resterr.NewOIDCError(invalidClientOIDCErr, finalErr)
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

// OidcRegisterClient registers dynamically an OAuth 2.0 client with the VCS authorization server.
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
		return err
	}

	profile, err := c.profileService.GetProfile(profileID, profileVersion)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return resterr.NewCustomError(resterr.ProfileNotFound, err)
		}

		return resterr.NewSystemError(resterr.IssuerProfileSvcComponent, "GetProfile", err)
	}

	if profile.OIDCConfig == nil || !profile.OIDCConfig.EnableDynamicClientRegistration {
		return fmt.Errorf("dynamic client registration not supported")
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
		var regErr *clientmanager.RegistrationError

		if errors.As(err, &regErr) {
			return &resterr.RegistrationError{
				Code: string(regErr.Code),
				Err:  fmt.Errorf("%w", regErr),
			}
		}

		return resterr.NewSystemError(resterr.ClientManagerComponent, "Create", err)
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
		return fmt.Errorf("marshal register oauth client response: %w", err)
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

func hashToken(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}
