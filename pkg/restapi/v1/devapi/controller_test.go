package devapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/restapi/v1/devapi"
	"github.com/trustbloc/vcs/pkg/service/didconfiguration"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
)

func TestController(t *testing.T) {
	route := NewMockrouter(gomock.NewController(t))

	route.EXPECT().GET("/:profileType/profiles/:profileID/well-known/did-config", gomock.Any()).Return(nil)
	route.EXPECT().GET("/request-object/:uuid", gomock.Any()).Return(nil)
	assert.NotNil(t, devapi.NewController(&devapi.Config{}, route))
}

func TestDidConfig(t *testing.T) {
	route := NewMockrouter(gomock.NewController(t))
	route.EXPECT().GET(gomock.Any(), gomock.Any()).AnyTimes()
	did := NewMockdidConfigService(gomock.NewController(t))

	c := devapi.NewController(&devapi.Config{
		DidConfigService: did,
	}, route)

	did.EXPECT().DidConfig(gomock.Any(), didconfiguration.ProfileTypeIssuer, "123").Return(nil, nil)
	assert.NoError(t, c.DidConfig(echoContext(), "issuer", "123"))
}

func TestRequestObjectByUUID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		route := NewMockrouter(gomock.NewController(t))
		route.EXPECT().GET(gomock.Any(), gomock.Any()).AnyTimes()
		store := NewMockrequestObjectStoreService(gomock.NewController(t))

		c := devapi.NewController(&devapi.Config{
			RequestObjectStoreService: store,
		}, route)

		store.EXPECT().Get(gomock.Any(), "123").Return(&requestobject.RequestObject{}, nil)
		assert.NoError(t, c.RequestObjectByUuid(echoContext(), "123"))
	})

	t.Run("not found", func(t *testing.T) {
		route := NewMockrouter(gomock.NewController(t))
		route.EXPECT().GET(gomock.Any(), gomock.Any()).AnyTimes()
		store := NewMockrequestObjectStoreService(gomock.NewController(t))

		c := devapi.NewController(&devapi.Config{
			RequestObjectStoreService: store,
		}, route)

		ct := echoContext()
		store.EXPECT().Get(gomock.Any(), "123").Return(nil, requestobject.ErrDataNotFound)
		assert.ErrorContains(t, c.RequestObjectByUuid(ct, "123"), "data not found")

		assert.Equal(t, http.StatusNotFound, ct.Response().Status)
	})
}

func echoContext() echo.Context {
	e := echo.New()

	var body io.Reader = http.NoBody

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}
