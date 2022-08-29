/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../api/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package verifier_test -source=controller.go -mock_names profileService=MockProfileService

package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/trustbloc/vcs/pkg/verifier"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type profileService interface {
	Create(profile *verifier.Profile) (*verifier.Profile, error)
	Update(profile *verifier.ProfileUpdate) (*verifier.Profile, error)
	Delete(profileID verifier.ProfileID) error
	GetProfile(profileID verifier.ProfileID) (*verifier.Profile, error)
	ActivateProfile(profileID verifier.ProfileID) error
	DeactivateProfile(profileID verifier.ProfileID) error
	GetAllProfiles(orgID string) ([]*verifier.Profile, error)
}

// Controller for Verifier Profile Management API.
type Controller struct {
	profileSvc profileService
}

// NewController creates a new controller for Verifier Profile Management API.
func NewController(profileSvc profileService) *Controller {
	return &Controller{
		profileSvc: profileSvc,
	}
}

// GetVerifierProfiles gets all verifier profiles for organization.
// GET /verifier/profiles.
func (c *Controller) GetVerifierProfiles(ctx echo.Context) error {
	// TODO: resolve orgID from auth token
	authHeader := ctx.Request().Header.Get("Authorization")
	if authHeader == "" || !strings.Contains(authHeader, "Bearer") {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing authorization")
	}

	orgID := authHeader[len("Bearer "):] // for now assume that token is just plain orgID

	profiles, err := c.profileSvc.GetAllProfiles(orgID)
	if err != nil {
		return fmt.Errorf("failed to get verifier profiles: %w", err)
	}

	var verifierProfiles []*VerifierProfile

	for _, profile := range profiles {
		verifierProfiles = append(verifierProfiles, mapProfile(profile))
	}

	return ctx.JSON(http.StatusOK, verifierProfiles)
}

// PostVerifierProfiles creates a new verifier profile.
// POST /verifier/profiles.
func (c *Controller) PostVerifierProfiles(ctx echo.Context) error {
	var body CreateVerifierProfileData

	if err := ctx.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	createdProfile, err := c.profileSvc.Create(mapCreateVerifierProfileData(&body))
	if err != nil {
		return fmt.Errorf("failed to create verifier profile: %w", err)
	}

	return ctx.JSON(http.StatusOK, mapProfile(createdProfile))
}

// DeleteVerifierProfilesProfileID deletes profile from VCS storage.
// DELETE /verifier/profiles/{profileID}.
func (c *Controller) DeleteVerifierProfilesProfileID(_ echo.Context, profileID string) error {
	if err := c.profileSvc.Delete(profileID); err != nil {
		return fmt.Errorf("failed to delete verifier profile: %w", err)
	}

	return nil
}

// GetVerifierProfilesProfileID gets profile by ID.
// GET /verifier/profiles/{profileID}.
func (c *Controller) GetVerifierProfilesProfileID(ctx echo.Context, profileID string) error {
	profile, err := c.profileSvc.GetProfile(profileID)
	if err != nil {
		if errors.Is(err, verifier.ErrProfileNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}

		return fmt.Errorf("failed to get verifier profile: %w", err)
	}

	return ctx.JSON(http.StatusOK, mapProfile(profile))
}

// PutVerifierProfilesProfileID updates profile.
// PUT /verifier/profiles/{profileID}.
func (c *Controller) PutVerifierProfilesProfileID(ctx echo.Context, profileID string) error {
	var body UpdateVerifierProfileData

	if err := ctx.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	profileUpdate := mapUpdateVerifierProfileData(&body)
	profileUpdate.ID = profileID

	updatedProfile, err := c.profileSvc.Update(profileUpdate)
	if err != nil {
		return fmt.Errorf("failed to update verifier profile: %w", err)
	}

	return ctx.JSON(http.StatusOK, mapProfile(updatedProfile))
}

// PostVerifierProfilesProfileIDActivate activates profile.
// POST /verifier/profiles/{profileID}/activate.
func (c *Controller) PostVerifierProfilesProfileIDActivate(_ echo.Context, profileID string) error {
	if err := c.profileSvc.ActivateProfile(profileID); err != nil {
		return fmt.Errorf("failed to activate verifier profile: %w", err)
	}

	return nil
}

// PostVerifierProfilesProfileIDDeactivate deactivates profile.
// POST /verifier/profiles/{profileID}/deactivate.
func (c *Controller) PostVerifierProfilesProfileIDDeactivate(_ echo.Context, profileID string) error {
	if err := c.profileSvc.DeactivateProfile(profileID); err != nil {
		return fmt.Errorf("failed to deactivate verifier profile: %w", err)
	}

	return nil
}

func mapCreateVerifierProfileData(data *CreateVerifierProfileData) *verifier.Profile {
	profile := &verifier.Profile{
		Name:           data.Name,
		OrganizationID: data.OrganizationID,
		Checks:         mapChecks(data.Checks),
	}

	if data.Url != nil {
		profile.URL = *data.Url
	}

	if data.OidcConfig != nil {
		profile.OIDCConfig = *data.OidcConfig
	}

	return profile
}

func mapUpdateVerifierProfileData(data *UpdateVerifierProfileData) *verifier.ProfileUpdate {
	profileUpdate := &verifier.ProfileUpdate{}

	if data.Name != nil {
		profileUpdate.Name = *data.Name
	}

	if data.Url != nil {
		profileUpdate.URL = *data.Url
	}

	if data.Checks != nil {
		profileUpdate.Checks = mapChecks(*data.Checks)
	}

	if data.OidcConfig != nil {
		profileUpdate.OIDCConfig = *data.OidcConfig
	}

	return profileUpdate
}

type verifierChecks struct {
	Credential struct {
		Format []string `json:"format,omitempty"`
		Proof  bool     `json:"proof,omitempty"`
		Status *bool    `json:"status,omitempty"`
	} `json:"credential,omitempty"`

	Presentation struct {
		Format []string `json:"format,omitempty"`
		Proof  bool     `json:"proof,omitempty"`
	} `json:"presentation,omitempty"`
}

func mapChecks(m map[string]interface{}) *verifier.VerificationChecks {
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}

	var checks verifierChecks
	if err = json.Unmarshal(b, &checks); err != nil {
		return nil
	}

	vc := &verifier.VerificationChecks{
		Credential: &verifier.CredentialChecks{
			Proof:  checks.Credential.Proof,
			Status: checks.Credential.Status != nil && *checks.Credential.Status,
		},
		Presentation: &verifier.PresentationChecks{
			Proof: checks.Presentation.Proof,
		},
	}

	for _, format := range checks.Credential.Format {
		vc.Credential.Format = append(vc.Credential.Format, verifier.CredentialFormat(format))
	}

	for _, format := range checks.Presentation.Format {
		vc.Presentation.Format = append(vc.Presentation.Format, verifier.PresentationFormat(format))
	}

	return vc
}

func mapProfile(profile *verifier.Profile) *VerifierProfile {
	vp := &VerifierProfile{
		Id:             profile.ID,
		Name:           profile.Name,
		OrganizationID: profile.OrganizationID,
		Active:         profile.Active,
	}

	if profile.URL != "" {
		vp.Url = &profile.URL
	}

	if profile.Checks != nil {
		vc := VerifierChecks{}

		if profile.Checks.Credential != nil {
			for _, format := range profile.Checks.Credential.Format {
				vc.Credential.Format = append(vc.Credential.Format, VerifierChecksCredentialFormat(format))
			}

			vc.Credential.Proof = profile.Checks.Credential.Proof
			vc.Credential.Status = &profile.Checks.Credential.Status
		}

		if profile.Checks.Presentation != nil {
			for _, format := range profile.Checks.Presentation.Format {
				vc.Presentation.Format = append(vc.Presentation.Format, VerifierChecksPresentationFormat(format))
			}

			vc.Presentation.Proof = profile.Checks.Presentation.Proof
		}

		vp.Checks = vc
	}

	if profile.OIDCConfig != nil {
		c, ok := profile.OIDCConfig.(map[string]interface{})
		if ok {
			vp.OidcConfig = &c
		}
	}

	return vp
}
