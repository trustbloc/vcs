/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package verifier -source=controller.go -mock_names profileService=MockProfileService,verifyCredentialSvc=MockVerifyCredentialService

package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	"github.com/trustbloc/vcs/pkg/verifier"
)

const (
	verifierProfileSvcComponent  = "verifier.ProfileService"
	verifyCredentialSvcComponent = "verifycredential.Service"
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

type verifyCredentialSvc interface {
	VerifyCredential(credential *verifiable.Credential, opts *verifycredential.Options,
		profile *verifier.Profile) ([]verifycredential.CredentialsVerificationCheckResult, error)
}

type Config struct {
	VerifyCredentialSvc verifyCredentialSvc
	ProfileSvc          profileService
	DocumentLoader      ld.DocumentLoader
	VDR                 vdrapi.Registry
}

// Controller for Verifier Profile Management API.
type Controller struct {
	verifyCredentialSvc verifyCredentialSvc
	profileSvc          profileService
	documentLoader      ld.DocumentLoader
	vdr                 vdrapi.Registry
}

// NewController creates a new controller for Verifier Profile Management API.
func NewController(config *Config) *Controller {
	return &Controller{
		verifyCredentialSvc: config.VerifyCredentialSvc,
		profileSvc:          config.ProfileSvc,
		documentLoader:      config.DocumentLoader,
		vdr:                 config.VDR,
	}
}

// GetVerifierProfiles gets all verifier profiles for organization.
// GET /verifier/profiles.
func (c *Controller) GetVerifierProfiles(ctx echo.Context) error {
	orgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profiles, err := c.profileSvc.GetAllProfiles(orgID)
	if err != nil {
		return fmt.Errorf("get all profiles: %w", err)
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
	orgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	var body CreateVerifierProfileData

	if err = ctx.Bind(&body); err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "requestBody", err)
	}

	if body.OrganizationID != orgID {
		return resterr.NewValidationError(resterr.InvalidValue, "organizationID",
			fmt.Errorf("org id mismatch (want %q, got %q)", orgID, body.OrganizationID))
	}

	createdProfile, err := c.profileSvc.Create(mapCreateVerifierProfileData(&body))
	if err != nil {
		return fmt.Errorf("create profile: %w", err)
	}

	return ctx.JSON(http.StatusOK, mapProfile(createdProfile))
}

// DeleteVerifierProfilesProfileID deletes profile from VCS storage.
// DELETE /verifier/profiles/{profileID}.
func (c *Controller) DeleteVerifierProfilesProfileID(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	if err = c.profileSvc.Delete(profile.ID); err != nil {
		return fmt.Errorf("delete profile: %w", err)
	}

	return nil
}

// GetVerifierProfilesProfileID gets profile by ID.
// GET /verifier/profiles/{profileID}.
func (c *Controller) GetVerifierProfilesProfileID(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, mapProfile(profile))
}

// PutVerifierProfilesProfileID updates profile.
// PUT /verifier/profiles/{profileID}.
func (c *Controller) PutVerifierProfilesProfileID(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	var body UpdateVerifierProfileData

	if err = ctx.Bind(&body); err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "requestBody", err)
	}

	profileUpdate := mapUpdateVerifierProfileData(&body)
	profileUpdate.ID = profile.ID

	updatedProfile, err := c.profileSvc.Update(profileUpdate)
	if err != nil {
		return fmt.Errorf("update profile: %w", err)
	}

	return ctx.JSON(http.StatusOK, mapProfile(updatedProfile))
}

// PostVerifierProfilesProfileIDActivate activates profile.
// POST /verifier/profiles/{profileID}/activate.
func (c *Controller) PostVerifierProfilesProfileIDActivate(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	if err = c.profileSvc.ActivateProfile(profile.ID); err != nil {
		return fmt.Errorf("activate profile: %w", err)
	}

	return nil
}

// PostVerifierProfilesProfileIDDeactivate deactivates profile.
// POST /verifier/profiles/{profileID}/deactivate.
func (c *Controller) PostVerifierProfilesProfileIDDeactivate(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	if err = c.profileSvc.DeactivateProfile(profile.ID); err != nil {
		return fmt.Errorf("deactivate profile: %w", err)
	}

	return nil
}

// PostVerifyCredentials Verify credential
// (POST /verifier/profiles/{profileID}/credentials/verify).
func (c *Controller) PostVerifyCredentials(ctx echo.Context, profileID string) error {
	var body VerifyCredentialData

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.verifyCredential(ctx, &body, profileID))
}

func (c *Controller) verifyCredential(ctx echo.Context, body *VerifyCredentialData,
	profileID string) (*VerifyCredentialResponse, error) {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return nil, err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return nil, err
	}

	credential, err := vc.ValidateCredential(body.Credential, profile.Checks.Credential.Format,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(c.vdr).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader))

	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	verRes, err := c.verifyCredentialSvc.VerifyCredential(credential, getVerifyCredentialOptions(body.Options), profile)
	if err != nil {
		return nil, resterr.NewSystemError(verifyCredentialSvcComponent, "VerifyCredential", err)
	}

	return mapVerifyCredentialChecks(verRes), nil
}

func (c *Controller) accessProfile(profileID string, oidcOrgID string) (*verifier.Profile, error) {
	profile, err := c.profileSvc.GetProfile(profileID)
	if errors.Is(err, verifier.ErrProfileNotFound) {
		return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
			fmt.Errorf("profile with given id %s, doesn't exist", profileID))
	}

	if err != nil {
		return nil, resterr.NewSystemError(verifierProfileSvcComponent, "GetProfile", err)
	}

	// Profiles of other organization is not visible.
	if profile.OrganizationID != oidcOrgID {
		return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
			fmt.Errorf("profile with given id %s, doesn't exist", profileID))
	}

	return profile, nil
}

func mapVerifyCredentialChecks(checks []verifycredential.CredentialsVerificationCheckResult) *VerifyCredentialResponse {
	result := &VerifyCredentialResponse{}
	for _, check := range checks {
		result.Checks = append(result.Checks, VerifyCredentialCheckResult{
			Check:              check.Check,
			Error:              check.Error,
			VerificationMethod: check.VerificationMethod,
		})
	}

	return result
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

	vchecks := &verifier.VerificationChecks{
		Credential: &verifier.CredentialChecks{
			Proof:  checks.Credential.Proof,
			Status: checks.Credential.Status != nil && *checks.Credential.Status,
		},
		Presentation: &verifier.PresentationChecks{
			Proof: checks.Presentation.Proof,
		},
	}

	for _, format := range checks.Credential.Format {
		vchecks.Credential.Format = append(vchecks.Credential.Format, vc.Format(format))
	}

	for _, format := range checks.Presentation.Format {
		vchecks.Presentation.Format = append(vchecks.Presentation.Format, verifier.PresentationFormat(format))
	}

	return vchecks
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

func getVerifyCredentialOptions(options *VerifyCredentialOptions) *verifycredential.Options {
	result := &verifycredential.Options{}
	if options == nil {
		return result
	}
	if options.Challenge != nil {
		result.Challenge = *options.Challenge
	}
	if options.Domain != nil {
		result.Domain = *options.Domain
	}

	return result
}
