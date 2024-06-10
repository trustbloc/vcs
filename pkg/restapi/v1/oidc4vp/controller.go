/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package oidc4vp_test . HTTPClient

package oidc4vp

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel/trace"
)

var logger = log.New("oidc4vp")

const (
	oidc4VPCheckEndpoint = "/verifier/interactions/authorization-response"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds configuration options for Controller.
type Config struct {
	HTTPClient      HTTPClient
	ExternalHostURL string
	Tracer          trace.Tracer
}

// Controller for OIDC credential issuance API.
type Controller struct {
	httpClient      HTTPClient
	internalHostURL string
	tracer          trace.Tracer
}

// NewController creates a new Controller instance.
func NewController(config *Config) *Controller {
	return &Controller{
		httpClient:      config.HTTPClient,
		internalHostURL: config.ExternalHostURL,
		tracer:          config.Tracer,
	}
}

// PresentAuthorizationResponse (POST /oidc/present).
func (c *Controller) PresentAuthorizationResponse(e echo.Context) error {
	request := e.Request()

	ctx, span := c.tracer.Start(request.Context(), "PresentAuthorizationResponse")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost,
		c.internalHostURL+oidc4VPCheckEndpoint,
		request.Body,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(e.Request().Context(), resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", respBytes)
	}

	return nil
}

// closeResponseBody closes the response body.
func closeResponseBody(ctx context.Context, respBody io.Closer) {
	err := respBody.Close()
	if err != nil {
		logger.Errorc(ctx, "Failed to close response body", log.WithError(err))
	}
}
