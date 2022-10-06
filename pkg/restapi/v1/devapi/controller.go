/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package devapi -source=controller.go -mock_names didConfigService=MockDidConfigService

package devapi

import (
	"context"
	"strings"

	"github.com/labstack/echo/v4"

	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/didconfiguration"
)

type didConfigService interface {
	DidConfig(
		ctx context.Context,
		profileType didconfiguration.ProfileType,
		profileID string,
		contextUrl string,
	) (*didconfiguration.DidConfiguration, error)
}

type Config struct {
	DidConfigService didConfigService
}

type Controller struct {
	didConfigService didConfigService
}

func NewController(
	config *Config,
) *Controller {
	return &Controller{
		didConfigService: config.DidConfigService,
	}
}

// DidConfig requests well-known DID config.
// GET /{profileType}/profiles/{profileID}/well-known/did-config.
func (c *Controller) DidConfig(ctx echo.Context, profileType string, profileID string) error {
	var contextUrl strings.Builder

	if scheme := ctx.Request().URL.Scheme; len(scheme) > 0 {
		contextUrl.WriteString(scheme + "://")
	} else {
		contextUrl.WriteString("https://")
	}

	if hostName := ctx.Request().URL.Hostname(); len(hostName) > 0 {
		contextUrl.WriteString(hostName + "/")
	} else {
		contextUrl.WriteString("localhost")
	}

	contextUrl.WriteString(ctx.Request().URL.Path)

	return apiUtil.WriteOutput(ctx)(c.didConfigService.DidConfig(ctx.Request().Context(),
		didconfiguration.ProfileType(strings.ToLower(profileType)),
		profileID,
		contextUrl.String()))
}
