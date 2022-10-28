/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package oidc4vc_test -source=controller.go -mock_names oidc4vcService=MockOIDC4VCService

package oidc4vc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/restapiclient"
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type oidc4VCStateStorage interface {
	StoreAuthorizationState(
		ctx context.Context,
		opState string,
		auth oidc4vc.OIDC4AuthorizationState,
		params ...func(insertOptions *oidc4vc.InsertOptions),
	) error
	GetAuthorizationState(
		ctx context.Context,
		opState string,
	) (*oidc4vc.OIDC4AuthorizationState, error)
}

type credentialInteractionAPIClient interface {
	// PrepareClaimDataAuthorization performs claim data issuance authorization on behalf of
	// resource owner (wallet user) for authorization code flow.
	PrepareClaimDataAuthorization(
		ctx context.Context,
		req *restapiclient.PrepareClaimDataAuthorizationRequest,
	) (*restapiclient.PrepareClaimDataAuthorizationResponse, error)

	// StoreAuthorizationCode persists authorization code from issuer's OIDC provider.
	StoreAuthorizationCode(
		ctx context.Context,
		req *restapiclient.StoreAuthorizationCodeRequest,
	) (*restapiclient.StoreAuthorizationCodeResponse, error)

	// PushAuthorizationRequest Validate PAR data
	PushAuthorizationRequest(
		ctx context.Context,
		req *restapiclient.PushAuthorizationRequest,
	) (*restapiclient.PushAuthorizationResponse, error)
}

// Config holds configuration options for Controller.
type Config struct {
	OAuth2Provider                 fosite.OAuth2Provider
	CredentialInteractionAPIClient credentialInteractionAPIClient
	OIDC4VCStateStorage            oidc4VCStateStorage
}

// Controller for OpenID for VC Issuance API.
type Controller struct {
	oauth2Provider                 fosite.OAuth2Provider
	credentialInteractionAPIClient credentialInteractionAPIClient
	oidc4VCStateStorage            oidc4VCStateStorage
}

// NewController creates a new Controller instance.
func NewController(config *Config) *Controller {
	return &Controller{
		oauth2Provider:                 config.OAuth2Provider,
		credentialInteractionAPIClient: config.CredentialInteractionAPIClient,
		oidc4VCStateStorage:            config.OIDC4VCStateStorage,
	}
}

// PostOidcPar handles Pushed Authorization Request for OIDC4VC (POST /oidc/par).
func (c *Controller) PostOidcPar(e echo.Context) error {
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

	ad, err := validateAuthorizationDetails(par.AuthorizationDetails)
	if err != nil {
		return resterr.NewFositeError(resterr.FositePARError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	_, err = c.credentialInteractionAPIClient.PushAuthorizationRequest(ctx, &restapiclient.PushAuthorizationRequest{
		OpState:        par.OpState,
		CredentialType: ad.CredentialType,
		Format:         string(ad.Format),
	})

	if err != nil {
		return resterr.NewFositeError(resterr.FositePARError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	resp, err := c.oauth2Provider.NewPushedAuthorizeResponse(ctx, ar, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewFositeError(resterr.FositePARError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	c.oauth2Provider.WritePushedAuthorizeResponse(ctx, e.Response().Writer, ar, resp)

	return nil
}

func validateAuthorizationDetails(authorizationDetails string) (*oidc4vc.AuthorizationDetails, error) {
	var param AuthorizationDetails

	if err := json.Unmarshal([]byte(authorizationDetails), &param); err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "authorization_details", err)
	}

	if param.Type != "openid_credential" {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "authorization_details.type",
			errors.New("type should be 'openid_credential'"))
	}

	ad := &oidc4vc.AuthorizationDetails{
		Type:           param.Type,
		CredentialType: param.CredentialType,
		Locations:      lo.FromPtr(param.Locations),
	}

	if param.Format != nil {
		vcFormat, err := common.ValidateVCFormat(common.VCFormat(*param.Format))
		if err != nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "authorization_details.format", err)
		}

		ad.Format = vcFormat
	}

	return ad, nil
}

// GetOidcAuthorize handles Authorization Request (GET /oidc/authorize).
func (c *Controller) GetOidcAuthorize(e echo.Context, params GetOidcAuthorizeParams) error {
	req := e.Request()
	ctx := req.Context()

	if params.OpState == nil || len(*params.OpState) == 0 {
		return apiUtil.WriteOutput(e)(nil, errors.New("op_state is required"))
	}

	ar, err := c.oauth2Provider.NewAuthorizeRequest(ctx, req)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	ar.(*fosite.AuthorizeRequest).State = *params.OpState

	authZResponse, authZErr := c.credentialInteractionAPIClient.PrepareClaimDataAuthorization(
		ctx,
		&restapiclient.PrepareClaimDataAuthorizationRequest{
			OpState: *params.OpState,
		},
	)
	if authZErr != nil {
		return authZErr
	}

	resp, err := c.oauth2Provider.NewAuthorizeResponse(ctx, ar, new(fosite.DefaultSession))

	if err != nil {
		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	if storeErr := c.oidc4VCStateStorage.StoreAuthorizationState(
		ctx,
		*params.OpState,
		oidc4vc.OIDC4AuthorizationState{
			RedirectURI: ar.GetRedirectURI(),
			RespondMode: string(ar.GetResponseMode()),
			AuthorizeResponse: oidc4vc.OIDC4AuthResponse{
				Header:     resp.GetHeader(),
				Parameters: resp.GetParameters(),
			},
		}); storeErr != nil {
		return storeErr
	}

	return e.Redirect(http.StatusSeeOther, authZResponse.RedirectURI)
}

// OidcRedirect handles oidc callback (GET /oidc/redirect).
func (c *Controller) OidcRedirect(e echo.Context, params OidcRedirectParams) error {
	req := e.Request()
	ctx := req.Context()

	_, authZErr := c.credentialInteractionAPIClient.StoreAuthorizationCode(ctx,
		&restapiclient.StoreAuthorizationCodeRequest{
			OpState: params.State,
			Code:    params.Code,
		})
	if authZErr != nil {
		return authZErr
	}

	resp, err := c.oidc4VCStateStorage.GetAuthorizationState(ctx, params.State)
	if err != nil {
		return apiUtil.WriteOutput(e)(nil, err)
	}

	responder := &fosite.AuthorizeResponse{}
	responder.Header = resp.AuthorizeResponse.Header
	responder.Parameters = resp.AuthorizeResponse.Parameters

	c.oauth2Provider.WriteAuthorizeResponse(ctx, e.Response().Writer, &fosite.AuthorizeRequest{
		RedirectURI:         resp.RedirectURI,
		ResponseMode:        fosite.ResponseModeType(resp.RespondMode),
		DefaultResponseMode: fosite.ResponseModeType(resp.RespondMode),
		State:               params.State,
	}, responder)

	return nil
}

// PostOidcToken handles Token Request (POST /oidc/token).
func (c *Controller) PostOidcToken(e echo.Context) error {
	req := e.Request()
	ctx := req.Context()

	ar, err := c.oauth2Provider.NewAccessRequest(ctx, req, new(fosite.DefaultSession))
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAccessError, e, c.oauth2Provider, err).WithAccessRequester(ar)
	}

	resp, err := c.oauth2Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAccessError, e, c.oauth2Provider, err).WithAccessRequester(ar)
	}

	c.oauth2Provider.WriteAccessResponse(ctx, e.Response().Writer, ar, resp)

	return nil
}
