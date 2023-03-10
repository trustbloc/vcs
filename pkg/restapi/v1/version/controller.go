/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package version

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

//go:generate mockgen -destination controller_mocks_test.go -package version_test -source=controller.go

type router interface {
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

type Config struct {
	Version       string
	ServerVersion string
}

type Controller struct {
	version       string
	serverVersion string
	cslStore      cslStore
}

type versionResponse struct {
	Version string `json:"version"`
}

type serverVersionResponse struct {
	Version string `json:"version"`
}

type cslStore interface {
	DeleteLatestListID() error
}

func NewController(router router, cfg Config, cslStore cslStore) *Controller {
	c := &Controller{
		cslStore:      cslStore,
		version:       cfg.Version,
		serverVersion: cfg.ServerVersion,
	}

	router.GET("/version", c.Version)
	router.GET("/version/system", c.ServerVersion)
	router.GET("/listid/cleanup", c.CleanupListID)

	return c
}

func (c *Controller) Version(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, versionResponse{Version: c.version})
}

func (c *Controller) ServerVersion(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, serverVersionResponse{Version: c.serverVersion})
}

func (c *Controller) CleanupListID(ctx echo.Context) error {
	err := c.cslStore.DeleteLatestListID()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError,
			map[string]string{"message": "failed to cleanup ListID", "error": err.Error()})
	}

	return ctx.JSON(http.StatusOK, map[string]string{"status": "OK"})
}
