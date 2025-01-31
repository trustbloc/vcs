/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package devapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/trustbloc/logutil-go/pkg/log"

	oidc4cierr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4ci"
	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/didconfiguration"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
)

//go:generate mockgen -destination controller_mocks_test.go -package devapi_test -source=controller.go

var logger = log.New("oidc4vp")

type didConfigService interface {
	DidConfig(
		ctx context.Context,
		profileType didconfiguration.ProfileType,
		profileID string,
		profileVersion string,
	) (*didconfiguration.DidConfiguration, error)
}

type requestObjectStoreService interface {
	Get(ctx context.Context, id string) (*requestobject.RequestObject, error)
}

type Config struct {
	DidConfigService          didConfigService
	RequestObjectStoreService requestObjectStoreService
}

type Controller struct {
	didConfigService          didConfigService
	requestObjectStoreService requestObjectStoreService
}

type router interface {
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

func NewController(
	config *Config,
	router router,
) *Controller {
	c := &Controller{
		didConfigService:          config.DidConfigService,
		requestObjectStoreService: config.RequestObjectStoreService,
	}

	router.GET("/:profileType/profiles/:profileID/:profileVersion/well-known/did-config",
		func(ctx echo.Context) error {
			return c.DidConfig(ctx,
				ctx.Param("profileType"), ctx.Param("profileID"), ctx.Param("profileVersion"))
		})

	router.GET("/request-object/:uuid", func(ctx echo.Context) error {
		return c.RequestObjectByUuid(ctx, ctx.Param("uuid"))
	})

	return c
}

// DidConfig requests well-known DID config.
// GET /{profileType}/profiles/{profileID}/{profileVersion}/well-known/did-config.
func (c *Controller) DidConfig(ctx echo.Context, profileType string, profileID, profileVersion string) error {
	didConfig, err := c.didConfigService.DidConfig(ctx.Request().Context(),
		didconfiguration.ProfileType(strings.ToLower(profileType)),
		profileID, profileVersion)
	if err != nil {
		return oidc4cierr.NewBadRequestError(err).
			WithErrorPrefix("get did config").
			UsePublicAPIResponse()
	}

	return apiUtil.WriteOutput(ctx)(didConfig, nil)
}

// RequestObjectByUuid Receive request object by uuid.
// GET /request-object/{uuid}.
func (c *Controller) RequestObjectByUuid(ctx echo.Context, uuid string) error { //nolint:stylecheck,revive
	logger.Infoc(ctx.Request().Context(), "RequestObjectByUuid begin")

	record, err := c.requestObjectStoreService.Get(ctx.Request().Context(), uuid)
	if err != nil {
		oidc4ciErr := oidc4cierr.NewBadRequestError(err)

		if errors.Is(err, requestobject.ErrDataNotFound) {
			oidc4ciErr = oidc4cierr.NewNotFoundError(err)
		}

		return oidc4ciErr.UsePublicAPIResponse()
	}

	logger.Infoc(ctx.Request().Context(), "RequestObjectByUuid end")

	return ctx.String(http.StatusOK, record.Content)
}
