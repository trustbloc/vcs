/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package verifier -source=controller.go -mock_names profileService=MockProfileService,verifyCredentialSvc=MockVerifyCredentialService,kmsRegistry=MockKMSRegistry

package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	"github.com/trustbloc/vcs/pkg/verifier"
)

const (
	verifierProfileSvcComponent  = "verifier.ProfileService"
	verifyCredentialSvcComponent = "verifycredential.Service"
	kmsRegistryComponent         = "kms.Registry"
)

type PresentationDefinition = json.RawMessage

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type kmsManager = kms.VCSKeyManager

type kmsRegistry interface {
	GetKeyManager(config *kms.Config) (kmsManager, error)
}

type profileService interface {
	Create(profile *verifier.Profile, presentationDefinitions []*presexch.PresentationDefinition) (
		*verifier.Profile, error)
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
	KMSRegistry         kmsRegistry
	DocumentLoader      ld.DocumentLoader
	VDR                 vdrapi.Registry
}

// Controller for Verifier Profile Management API.
type Controller struct {
	verifyCredentialSvc verifyCredentialSvc
	profileSvc          profileService
	kmsRegistry         kmsRegistry
	documentLoader      ld.DocumentLoader
	vdr                 vdrapi.Registry
}

// NewController creates a new controller for Verifier Profile Management API.
func NewController(config *Config) *Controller {
	return &Controller{
		verifyCredentialSvc: config.VerifyCredentialSvc,
		profileSvc:          config.ProfileSvc,
		kmsRegistry:         config.KMSRegistry,
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
		outProfile, err := mapProfile(profile)
		if err != nil {
			return err
		}
		verifierProfiles = append(verifierProfiles, outProfile)
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

	if err = util.ReadBody(ctx, &body); err != nil {
		return err
	}

	if body.OrganizationID != orgID {
		return resterr.NewValidationError(resterr.InvalidValue, "organizationID",
			fmt.Errorf("org id mismatch (want %q, got %q)", orgID, body.OrganizationID))
	}

	profile, presentationDefinitions, err := c.validateCreateVerifierProfileData(&body)
	if err != nil {
		return err
	}

	createdProfile, err := c.profileSvc.Create(profile, presentationDefinitions)
	if err != nil {
		return resterr.NewSystemError(verifierProfileSvcComponent, "Create",
			fmt.Errorf("create profile: %w", err))
	}

	return util.WriteOutput(ctx)(mapProfile(createdProfile))
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

	return util.WriteOutput(ctx)(mapProfile(profile))
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

	profileUpdate, err := validateUpdateVerifierProfileData(&body, profile.ID)
	if err != nil {
		return err
	}

	updatedProfile, err := c.profileSvc.Update(profileUpdate)
	if err != nil {
		return fmt.Errorf("update profile: %w", err)
	}

	return util.WriteOutput(ctx)(mapProfile(updatedProfile))
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

func validatePresentationDefinition(rawPD PresentationDefinition) (*presexch.PresentationDefinition, error) {
	pd := &presexch.PresentationDefinition{}

	err := json.Unmarshal(rawPD, &pd)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "presentationDefinition", err)
	}

	err = pd.ValidateSchema()
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "presentationDefinition", err)
	}
	return pd, nil
}

func (c *Controller) validateCreateVerifierProfileData(data *CreateVerifierProfileData) (
	*verifier.Profile, []*presexch.PresentationDefinition, error) {
	checks, err := validateChecks(data.Checks)
	if err != nil {
		return nil, nil, err
	}

	kmsConfig, err := common.ValidateKMSConfig(data.KmsConfig)
	if err != nil {
		return nil, nil, err
	}

	keyManager, err := c.kmsRegistry.GetKeyManager(kmsConfig)
	if err != nil {
		return nil, nil, resterr.NewSystemError(kmsRegistryComponent, "GetKeyManager", err)
	}

	oidc4VPConfig, err := validateOIDC4VPConfig(data.OidcConfig, keyManager.SupportedKeyTypes())
	if err != nil {
		return nil, nil, err
	}

	var presentationDefinitions []*presexch.PresentationDefinition

	if data.PresentationDefinitions != nil {
		for _, rawPD := range *data.PresentationDefinitions {
			pd, err := validatePresentationDefinition(rawPD)
			if err != nil {
				return nil, nil, err
			}

			presentationDefinitions = append(presentationDefinitions, pd)
		}
	}

	profile := &verifier.Profile{
		Name:           data.Name,
		OrganizationID: data.OrganizationID,
		Checks:         checks,
		KMSConfig:      kmsConfig,
		OIDCConfig:     oidc4VPConfig,
	}

	if data.Url != nil {
		profile.URL = *data.Url
	}

	return profile, presentationDefinitions, nil
}

func validateOIDC4VPConfig(cfg *OIDC4VPConfig, supportedKeyTypes []arieskms.KeyType) (*verifier.OIDC4VPConfig, error) {
	if cfg == nil {
		return nil, nil //nolint:nilnil
	}

	signingAlgorithm, err := vc.ValidateSignatureAlgorithm(vc.Jwt, cfg.RoSigningAlgorithm, supportedKeyTypes)

	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "oidcConfig.roSigningAlgorithm",
			fmt.Errorf("issuer profile service: create profile failed %w", err))
	}

	didMethod, err := common.ValidateDIDMethod(cfg.DidMethod)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "oidcConfig.didMethod", err)
	}

	return &verifier.OIDC4VPConfig{
		DIDMethod:          didMethod,
		ROSigningAlgorithm: signingAlgorithm,
	}, nil
}

func mapVerifyCredentialChecks(checks []verifycredential.CredentialsVerificationCheckResult) *VerifyCredentialResponse {
	if len(checks) == 0 {
		return &VerifyCredentialResponse{}
	}

	var checkList []VerifyCredentialCheckResult
	for _, check := range checks {
		checkList = append(checkList, VerifyCredentialCheckResult{
			Check:              check.Check,
			Error:              check.Error,
			VerificationMethod: check.VerificationMethod,
		})
	}

	return &VerifyCredentialResponse{
		Checks: &checkList,
	}
}

func validateUpdateVerifierProfileData(data *UpdateVerifierProfileData, profileID verifier.ProfileID) (
	*verifier.ProfileUpdate, error) {
	profileUpdate := &verifier.ProfileUpdate{
		ID: profileID,
	}

	if data.Name != nil {
		profileUpdate.Name = *data.Name
	}

	if data.Url != nil {
		profileUpdate.URL = *data.Url
	}

	if data.Checks != nil {
		checks, err := validateChecks(*data.Checks)
		if err != nil {
			return nil, err
		}

		profileUpdate.Checks = checks
	}

	return profileUpdate, nil
}

func validateChecks(checks VerifierChecks) (*verifier.VerificationChecks, error) {
	vchecks := &verifier.VerificationChecks{
		Credential: verifier.CredentialChecks{
			Proof:  checks.Credential.Proof,
			Status: checks.Credential.Status != nil && *checks.Credential.Status,
		},
	}

	for _, rawFormat := range checks.Credential.Format {
		format, err := common.ValidateVCFormat(rawFormat)
		if err != nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "checks.credential.format", err)
		}

		vchecks.Credential.Format = append(vchecks.Credential.Format, format)
	}

	var presentationChecks *verifier.PresentationChecks

	if checks.Presentation != nil {
		presentationChecks = &verifier.PresentationChecks{
			Proof: checks.Presentation.Proof,
		}

		for _, rawFormat := range checks.Presentation.Format {
			format, err := common.ValidateVPFormat(rawFormat)
			if err != nil {
				return nil, resterr.NewValidationError(resterr.InvalidValue, "checks.presentation.format", err)
			}
			presentationChecks.Format = append(presentationChecks.Format, format)
		}
	}

	vchecks.Presentation = presentationChecks

	return vchecks, nil
}

func mapChecks(checks *verifier.VerificationChecks) (*VerifierChecks, error) {
	vchecks := &VerifierChecks{}
	vchecks.Credential.Proof = checks.Credential.Proof
	vchecks.Credential.Status = &checks.Credential.Status

	for _, rawFormat := range checks.Credential.Format {
		format, err := common.MapToVCFormat(rawFormat)
		if err != nil {
			return nil, resterr.NewSystemError(verifierProfileSvcComponent, "MapToVCFormat", err)
		}

		vchecks.Credential.Format = append(vchecks.Credential.Format, format)
	}

	if checks.Presentation != nil {
		vchecks.Presentation = &PresentationChecks{Proof: checks.Presentation.Proof}

		for _, rawFormat := range checks.Presentation.Format {
			format, err := common.MapToVPFormat(rawFormat)
			if err != nil {
				return nil, resterr.NewSystemError(verifierProfileSvcComponent, "MapToVPFormat", err)
			}
			vchecks.Presentation.Format = append(vchecks.Presentation.Format, format)
		}
	}

	return vchecks, nil
}

func mapProfile(profile *verifier.Profile) (*VerifierProfile, error) {
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
		checks, err := mapChecks(profile.Checks)
		if err != nil {
			return nil, err
		}
		vp.Checks = *checks
	}

	return vp, nil
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
