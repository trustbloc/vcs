package version

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

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
}

type versionResponse struct {
	Version string `json:"version"`
}

type serverVersionResponse struct {
	Version string `json:"version"`
}

func NewController(router router, cfg Config) *Controller {
	c := &Controller{
		version:       cfg.Version,
		serverVersion: cfg.ServerVersion,
	}

	router.GET("/version", func(ctx echo.Context) error {
		return c.Version(ctx)
	})
	router.GET("/version/system", func(ctx echo.Context) error {
		return c.ServerVersion(ctx)
	})

	return c
}

func (c *Controller) Version(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, versionResponse{Version: c.version})
}

func (c *Controller) ServerVersion(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, serverVersionResponse{Version: c.serverVersion})
}
