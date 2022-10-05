/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package devapi -source=controller.go -mock_names verifierProfileService=MockVerifierProfileService,issuerProfileService=MockIssuerProfileService,issueCredentialService=MockIssueCredentialService

package devapi

import (
	"context"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/labstack/echo/v4"
	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/wellknown"

	"strings"
)

type wellKnownService interface {
	DidConfig(
		ctx context.Context,
		profileType wellknown.ProfileType,
		profileID string,
		contextUrl string,
	) (*verifiable.Credential, error)
}

type Config struct {
	WellKnownService wellKnownService
}

type Controller struct {
	wellKnownService wellKnownService
}

func NewController(
	config *Config,
) *Controller {
	return &Controller{
		wellKnownService: config.WellKnownService,
	}
}

// DidConfig requests well-known DID config.
// GET /{profileType}/profiles/{profileID}/well-known/did-config.
func (c *Controller) DidConfig(ctx echo.Context, profileType string, profileID string) error {
	return apiUtil.WriteOutput(ctx)(c.wellKnownService.DidConfig(ctx.Request().Context(),
		wellknown.ProfileType(strings.ToLower(profileType)),
		profileID,
		ctx.Request().URL.RequestURI()))
}
