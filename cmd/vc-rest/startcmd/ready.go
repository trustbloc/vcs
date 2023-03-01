package startcmd

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

const (
	readinessEndpoint = "/ready"
)

type readiness struct {
	isReady bool
}

func newReadinessController(internalEcho *echo.Echo) *readiness {
	r := &readiness{
		isReady: false,
	}

	internalEcho.GET(readinessEndpoint, func(c echo.Context) error {
		if r.isReady {
			return c.NoContent(http.StatusOK)
		}

		return c.NoContent(http.StatusForbidden)
	})

	return r
}

func (r *readiness) Ready(isReady bool) {
	r.isReady = isReady
}
