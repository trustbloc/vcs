/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package devapi -source=controller.go -mock_names didConfigService=MockDidConfigService,requestObjectStoreService=MockRequestObjectStoreService

package devapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/didconfiguration"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
)

type didConfigService interface {
	DidConfig(
		ctx context.Context,
		profileType didconfiguration.ProfileType,
		profileID string,
	) (*didconfiguration.DidConfiguration, error)
}

type requestObjectStoreService interface {
	Get(id string) (*requestobject.RequestObject, error)
}

type Config struct {
	DidConfigService          didConfigService
	RequestObjectStoreService requestObjectStoreService
}

type Controller struct {
	didConfigService          didConfigService
	requestObjectStoreService requestObjectStoreService
}

func NewController(
	config *Config,
) *Controller {
	return &Controller{
		didConfigService:          config.DidConfigService,
		requestObjectStoreService: config.RequestObjectStoreService,
	}
}

// DidConfig requests well-known DID config.
// GET /{profileType}/profiles/{profileID}/well-known/did-config.
func (c *Controller) DidConfig(ctx echo.Context, profileType string, profileID string) error {
	return apiUtil.WriteOutput(ctx)(c.didConfigService.DidConfig(ctx.Request().Context(),
		didconfiguration.ProfileType(strings.ToLower(profileType)),
		profileID))
}

// RequestObjectByUuid Receive request object by uuid.
// GET /request-object/{uuid}.
func (c *Controller) RequestObjectByUuid(ctx echo.Context, uuid string) error { //nolint:stylecheck,revive
	record, err := c.requestObjectStoreService.Get(uuid)

	if errors.Is(err, requestobject.ErrDataNotFound) {
		ctx.Response().Status = 404
	}

	if err != nil {
		return err
	}

	return ctx.String(http.StatusOK, record.Content)
}
