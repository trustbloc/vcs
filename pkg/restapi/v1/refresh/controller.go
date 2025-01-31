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
	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/utils"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4cierr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4ci"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type Config struct {
	RefreshService        CredentialRefreshService
	ProfileService        ProfileService
	ProofChecker          ProofChecker
	DocumentLoader        ld.DocumentLoader
	IssuerVCSPublicHost   string
	DataIntegrityVerifier *dataintegrity.Verifier
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
		return oidc4cierr.NewBadRequestError(err).WithOperation("read body")
	}

	opts := []verifiable.PresentationOpt{
		verifiable.WithPresJSONLDDocumentLoader(c.cfg.DocumentLoader),
		verifiable.WithPresProofChecker(c.cfg.ProofChecker),
	}

	if c.cfg.DataIntegrityVerifier != nil {
		opts = append(opts, verifiable.WithPresDataIntegrityVerifier(c.cfg.DataIntegrityVerifier))
	}

	pres, err := verifiable.ParsePresentation(
		req.VerifiablePresentation,
		opts...,
	)
	if err != nil {
		return oidc4cierr.NewBadRequestError(err).
			WithOperation("read body").
			WithIncorrectValue("verifiable_presentation")
	}

	targetIssuer, err := c.cfg.ProfileService.GetProfile(profileID, profileVersion)
	if err != nil {
		return oidc4cierr.NewBadRequestError(err).
			WithOperation("GetProfile").
			WithComponent(resterr.IssuerProfileSvcComponent).
			WithIncorrectValue("verifiable_presentation")
	}

	resp, err := c.cfg.RefreshService.GetRefreshedCredential(ctx.Request().Context(), pres, *targetIssuer)
	if err != nil {
		return oidc4cierr.NewBadRequestError(err).
			WithOperation("GetRefreshedCredential").
			WithComponent(resterr.IssuerCredentialRefreshSvcComponent).
			WithIncorrectValue("verifiable_presentation")
	}

	return ctx.JSON(http.StatusOK, GetRefreshedCredentialResp{
		VerifiableCredential: resp.Credential,
		IssuerURI:            resp.IssuerURL,
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
		return oidc4cierr.NewBadRequestError(err).
			WithOperation("GetProfile").
			WithComponent(resterr.IssuerProfileSvcComponent)
	}

	resp, err := c.cfg.RefreshService.RequestRefreshStatus(ctx.Request().Context(), params.CredentialID, *targetIssuer)
	if err != nil {
		return oidc4cierr.NewBadRequestError(err).
			WithOperation("RequestRefreshStatus").
			WithComponent(resterr.IssuerCredentialRefreshSvcComponent)
	}

	if resp == nil {
		return ctx.NoContent(http.StatusNoContent)
	}

	query, err := utils.StructureToMap(resp.VerifiablePresentationRequest.Query)
	if err != nil {
		return oidc4cierr.NewBadRequestError(err).
			WithOperation("StructureToMap").
			WithComponent(resterr.IssuerCredentialRefreshSvcComponent)
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
