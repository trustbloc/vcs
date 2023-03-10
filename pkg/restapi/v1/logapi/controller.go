/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logapi

import (
	"fmt"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/trustbloc/logutil-go/pkg/log"
)

//go:generate mockgen -destination controller_mocks_test.go -package logapi_test -source=controller.go

var logger = log.New("logapi")

type Controller struct {
}

type router interface {
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

func NewController(
	router router,
) *Controller {
	c := &Controller{}

	router.POST("/loglevels", func(ctx echo.Context) error {
		return c.PostLogLevels(ctx)
	})

	return c
}

// PostLogLevels updates log levels.
// (POST /loglevels).
func (c *Controller) PostLogLevels(ctx echo.Context) error {
	req := ctx.Request()

	logLevelBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	logLevels := string(logLevelBytes)

	if err := log.SetSpec(logLevels); err != nil {
		return fmt.Errorf("failed to set log spec: %w", err)
	}

	logger.Info(fmt.Sprintf("log levels modified to: %s", logLevels))
	return ctx.NoContent(http.StatusOK)
}
