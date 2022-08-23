/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../api/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package issuer_test -source=controller.go -mock_names profileService=MockProfileService

package issuer

import (
	"fmt"

	"github.com/labstack/echo/v4"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

// Controller for Issuer Profile Management API.
type Controller struct {
}

// NewController creates a new controller for Issuer Profile Management API.
func NewController() *Controller {
	return &Controller{}
}

// PostIssuerProfiles creates a new issuer profile.
// POST /issuer/profiles.
func (c *Controller) PostIssuerProfiles(ctx echo.Context) error {
	return fmt.Errorf("not implemented")
}

// DeleteIssuerProfilesProfileID deletes profile.
// DELETE /issuer/profiles/{profileID}.
func (c *Controller) DeleteIssuerProfilesProfileID(ctx echo.Context, profileID string) error {
	return fmt.Errorf("not implemented")
}

// GetIssuerProfilesProfileID gets a profile by ID.
// GET /issuer/profiles/{profileID}.
func (c *Controller) GetIssuerProfilesProfileID(ctx echo.Context, profileID string) error {
	return fmt.Errorf("not implemented")
}

// PutIssuerProfilesProfileID updates a profile.
// PUT /issuer/profiles/{profileID}.
func (c *Controller) PutIssuerProfilesProfileID(ctx echo.Context, profileID string) error {
	return fmt.Errorf("not implemented")
}

// PostIssuerProfilesProfileIDActivate activates a profile.
// POST /issuer/profiles/{profileID}/activate.
func (c *Controller) PostIssuerProfilesProfileIDActivate(ctx echo.Context, profileID string) error {
	return fmt.Errorf("not implemented")
}

// PostIssuerProfilesProfileIDDeactivate deactivates a profile.
// POST /issuer/profiles/{profileID}/deactivate.
func (c *Controller) PostIssuerProfilesProfileIDDeactivate(ctx echo.Context, profileID string) error {
	return fmt.Errorf("not implemented")
}
