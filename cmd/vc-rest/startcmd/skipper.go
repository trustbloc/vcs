package startcmd

import (
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	"strings"
)

func OApiSkipper(c echo.Context) bool {
	if c.Path() == devApiRequestObjectEndpoint || c.Path() == devApiDidConfigEndpoint {
		return true
	}
	if c.Path() == versionEndpoint || c.Path() == versionSystemEndpoint {
		return true
	}

	if c.Path() == logLevelsEndpoint {
		return true
	}
	if strings.Contains(c.Path(), profilerEndpoints) {
		return true
	}

	return echomw.DefaultSkipper(c)
}
