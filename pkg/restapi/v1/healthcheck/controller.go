/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../api/openapi.yaml

package healthcheck

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// Controller for health check API.
type Controller struct{}

// GetHealthcheck returns the health check status.
// GET /healthcheck.
func (c *Controller) GetHealthcheck(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, HealthCheckResponse{Status: "success"})
}
