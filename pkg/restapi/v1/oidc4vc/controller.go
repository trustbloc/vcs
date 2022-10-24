/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package oidc4vc_test -source=controller.go -mock_names oidc4VCService=MockOIDC4VCService

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
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type oidc4VCService interface {
	HandlePAR(ctx context.Context, opState string, ad *oidc4vc.AuthorizationDetails) (oidc4vc.TxID, error)
	HandleAuthorize(
		ctx context.Context,
		opState string,
		responder oidc4vc.InternalAuthorizationResponder,
	) (string, error)
}

// Config holds configuration options for Controller.
type Config struct {
	OAuth2Provider fosite.OAuth2Provider
	OIDC4VCService oidc4VCService
}

// Controller for OpenID for VC Issuance API.
type Controller struct {
	oauth2Provider fosite.OAuth2Provider
	oidc4VCService oidc4VCService
}

// NewController creates a new Controller instance.
func NewController(config *Config) (*Controller, error) {
	return &Controller{
		oauth2Provider: config.OAuth2Provider,
		oidc4VCService: config.OIDC4VCService,
	}, nil
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

	txID, err := c.oidc4VCService.HandlePAR(ctx, par.OpState, ad)
	if err != nil {
		return resterr.NewFositeError(resterr.FositePARError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	session := &oidc4vc.Session{
		DefaultSession: new(fosite.DefaultSession),
		TxID:           txID,
	}

	resp, err := c.oauth2Provider.NewPushedAuthorizeResponse(ctx, ar, session)
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

	session, ok := ar.GetSession().(*oidc4vc.Session)
	if !ok {
		session = &oidc4vc.Session{
			DefaultSession: new(fosite.DefaultSession),
		}
	}

	resp, err := c.oauth2Provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		return resterr.NewFositeError(resterr.FositeAuthorizeError, e, c.oauth2Provider, err).WithAuthorizeRequester(ar)
	}

	issuerRedirectURL, issuerErr := c.oidc4VCService.HandleAuthorize(
		ctx,
		*params.OpState,
		oidc4vc.InternalAuthorizationResponder{
			RedirectURI: ar.GetRedirectURI(),
			RespondMode: ar.GetResponseMode(),
			AuthorizeResponse: fosite.AuthorizeResponse{
				Header:     resp.GetHeader(),
				Parameters: resp.GetParameters(),
			},
		},
	)

	if issuerErr != nil {
		return apiUtil.WriteOutput(e)(nil, issuerErr)
	}

	return e.Redirect(http.StatusSeeOther, issuerRedirectURL)
}

// PostOidcToken handles Token Request (POST /oidc/token).
func (c *Controller) PostOidcToken(e echo.Context) error {
	req := e.Request()
	ctx := req.Context()

	session := &oidc4vc.Session{
		DefaultSession: new(fosite.DefaultSession),
	}

	ar, err := c.oauth2Provider.NewAccessRequest(ctx, req, session)
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
