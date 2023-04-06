package startcmd

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOApiSkipper(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		result bool
	}{
		{
			name:   "version endpoint",
			path:   "/version/system",
			result: true,
		},
		{
			name:   "versionSystem endpoint",
			path:   "/version",
			result: true,
		},
		{
			name:   "devApiRequestObject endpoint",
			path:   "/request-object/:uuid",
			result: true,
		},
		{
			name:   "logLevels endpoint",
			path:   "/loglevels",
			result: true,
		},
		{
			name:   "profiler endpoint",
			path:   "/debug/pprof/some/other/path",
			result: true,
		},
		{
			name:   "other endpoint",
			path:   "/some/other/path",
			result: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			ctx := echo.New().NewContext(req, httptest.NewRecorder())
			ctx.SetPath(tt.path)

			if got := OApiSkipper(ctx); got != tt.result {
				t.Errorf("OApiSkipper() = %v, want %v", got, tt.result)
			}
		})
	}
}
