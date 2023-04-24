/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package devapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/trustbloc/logutil-go/pkg/log"

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
	return apiUtil.WriteOutput(ctx)(c.didConfigService.DidConfig(ctx.Request().Context(),
		didconfiguration.ProfileType(strings.ToLower(profileType)),
		profileID, profileVersion))
}

// RequestObjectByUuid Receive request object by uuid.
// GET /request-object/{uuid}.
func (c *Controller) RequestObjectByUuid(ctx echo.Context, uuid string) error { //nolint:stylecheck,revive
	logger.Info(fmt.Sprintf("RequestObjectByUuid begin %s", uuid))
	record, err := c.requestObjectStoreService.Get(ctx.Request().Context(), uuid)

	if errors.Is(err, requestobject.ErrDataNotFound) {
		ctx.Response().Status = http.StatusNotFound
	}

	if err != nil {
		return err
	}

	logger.Info("RequestObjectByUuid end")
	return ctx.String(http.StatusOK, record.Content)
}
