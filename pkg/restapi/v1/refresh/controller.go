/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml

package refresh

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/utils"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type Config struct {
	RefreshService      CredentialRefreshService
	ProfileService      ProfileService
	ProofChecker        ProofChecker
	DocumentLoader      ld.DocumentLoader
	IssuerVCSPublicHost string
}
type Controller struct {
	cfg *Config
}

func NewController(cfg *Config) *Controller {
	return &Controller{
		cfg: cfg,
	}
}

// GetRefreshedCredential gets refreshed credentials (POST /refresh/{profileID}/{profileVersion}).
func (c *Controller) GetRefreshedCredential(
	ctx echo.Context,
	profileID string,
	profileVersion string,
	_ GetRefreshedCredentialParams,
) error {
	var req GetRefreshedCredentialReq
	if err := ctx.Bind(&req); err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "request", err)
	}

	pres, err := verifiable.ParsePresentation(req.VerifiablePresentation,
		verifiable.WithPresJSONLDDocumentLoader(c.cfg.DocumentLoader),
		verifiable.WithPresProofChecker(c.cfg.ProofChecker))
	if err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "verifiable_presentation", err)
	}

	targetIssuer, err := c.cfg.ProfileService.GetProfile(profileID, profileVersion)
	if err != nil {
		return resterr.NewSystemError(resterr.IssuerProfileSvcComponent, "GetProfile", err)
	}

	resp, err := c.cfg.RefreshService.GetRefreshedCredential(ctx.Request().Context(), pres, *targetIssuer)
	if err != nil {
		return resterr.NewSystemError(resterr.IssuerCredentialRefreshSvcComponent,
			"GetRefreshedCredential",
			err)
	}

	return ctx.JSON(http.StatusOK, GetRefreshedCredentialResp{
		VerifiableCredential: resp,
	})
}

// RequestRefreshStatus gets refresh status (GET /refresh/{profileID}/{profileVersion}).
func (c *Controller) RequestRefreshStatus(
	ctx echo.Context,
	issuerID string,
	profileVersion string,
	params RequestRefreshStatusParams,
) error {
	targetIssuer, err := c.cfg.ProfileService.GetProfile(issuerID, profileVersion)
	if err != nil {
		return resterr.NewSystemError(resterr.IssuerProfileSvcComponent, "GetProfile", err)
	}

	resp, err := c.cfg.RefreshService.RequestRefreshStatus(ctx.Request().Context(), params.CredentialID, *targetIssuer)
	if err != nil {
		return resterr.NewSystemError(resterr.IssuerCredentialRefreshSvcComponent, "RequestRefreshStatus",
			err)
	}

	if resp == nil {
		return ctx.NoContent(http.StatusNoContent)
	}

	query, err := utils.StructureToMap(resp.VerifiablePresentationRequest.Query)
	if err != nil {
		return resterr.NewSystemError(resterr.IssuerCredentialRefreshSvcComponent, "RequestRefreshStatus",
			err)
	}

	return ctx.JSON(http.StatusOK, &CredentialRefreshAvailableResponse{
		VerifiablePresentationRequest: VerifiablePresentationRequest{
			Challenge: resp.Challenge,
			Domain:    resp.Domain,
			Interact: RefreshServiceInteract{
				Service: []RefreshService{
					{
						ServiceEndpoint: fmt.Sprintf("%s%s", c.cfg.IssuerVCSPublicHost,
							ctx.Request().URL.String()),
						Type: resp.RefreshServiceType.Type,
					},
				},
			},
			Query: query,
		},
	})
}
