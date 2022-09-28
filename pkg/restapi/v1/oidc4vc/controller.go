/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
package oidc4vc

import (
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

// Config holds configuration options for Controller.
type Config struct {
	OAuth2Provider fosite.OAuth2Provider
}

// Controller for OpenID for VC Issuance API.
type Controller struct {
	oauth2Provider fosite.OAuth2Provider
}

// NewController creates a new Controller instance.
func NewController(config *Config) (*Controller, error) {
	return &Controller{
		oauth2Provider: config.OAuth2Provider,
	}, nil
}

// GetOidcAuthorize handles Authorization Request (GET /oidc/authorize).
func (c *Controller) GetOidcAuthorize(e echo.Context, params GetOidcAuthorizeParams) error {
	req := e.Request()
	ctx := req.Context()

	ar, err := c.oauth2Provider.NewAuthorizeRequest(ctx, req)
	if err != nil {
		c.oauth2Provider.WriteAuthorizeError(ctx, e.Response().Writer, ar, err)

		return nil
	}

	var session fosite.DefaultSession

	resp, err := c.oauth2Provider.NewAuthorizeResponse(ctx, ar, &session)
	if err != nil {
		c.oauth2Provider.WriteAuthorizeError(ctx, e.Response().Writer, ar, err)

		return nil
	}

	c.oauth2Provider.WriteAuthorizeResponse(ctx, e.Response().Writer, ar, resp)

	return nil
}

// PostOidcPar handles Pushed Authorization Request (POST /oidc/par).
func (c *Controller) PostOidcPar(e echo.Context) error {
	req := e.Request()
	ctx := req.Context()

	ar, err := c.oauth2Provider.NewPushedAuthorizeRequest(ctx, req)
	if err != nil {
		c.oauth2Provider.WritePushedAuthorizeError(ctx, e.Response().Writer, ar, err)

		return nil
	}

	var session fosite.DefaultSession

	resp, err := c.oauth2Provider.NewPushedAuthorizeResponse(ctx, ar, &session)
	if err != nil {
		c.oauth2Provider.WritePushedAuthorizeError(ctx, e.Response().Writer, ar, err)

		return nil
	}

	c.oauth2Provider.WritePushedAuthorizeResponse(ctx, e.Response().Writer, ar, resp)

	return nil
}

// PostOidcToken handles Token Request (POST /oidc/token).
func (c *Controller) PostOidcToken(e echo.Context) error {
	req := e.Request()
	ctx := req.Context()

	var session fosite.DefaultSession

	ar, err := c.oauth2Provider.NewAccessRequest(ctx, req, &session)
	if err != nil {
		c.oauth2Provider.WriteAccessError(ctx, e.Response().Writer, ar, err)

		return nil
	}

	resp, err := c.oauth2Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		c.oauth2Provider.WriteAccessError(ctx, e.Response().Writer, ar, err)

		return nil
	}

	c.oauth2Provider.WriteAccessResponse(ctx, e.Response().Writer, ar, resp)

	return nil
}
