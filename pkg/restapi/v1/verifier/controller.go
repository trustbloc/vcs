/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package verifier -source=controller.go -mock_names profileService=MockProfileService,verifyCredentialSvc=MockVerifyCredentialService,kmsRegistry=MockKMSRegistry,oidc4VPService=MockOIDC4VPService

package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vp"
	"github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

const (
	verifierProfileSvcComponent  = "verifier.ProfileService"
	verifyCredentialSvcComponent = "verifycredential.Service"
)

type PresentationDefinition = json.RawMessage

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type kmsManager = kms.VCSKeyManager

type kmsRegistry interface {
	GetKeyManager(config *kms.Config) (kmsManager, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Verifier, error)
}

type verifyCredentialSvc interface {
	VerifyCredential(credential *verifiable.Credential, opts *verifycredential.Options,
		profile *profileapi.Verifier) ([]verifycredential.CredentialsVerificationCheckResult, error)
}

type verifyPresentationSvc interface {
	VerifyPresentation(presentation *verifiable.Presentation, opts *verifypresentation.Options,
		profile *profileapi.Verifier) ([]verifypresentation.PresentationVerificationCheckResult, error)
}

type oidc4VPService interface {
	InitiateOidcInteraction(presentationDefinition *presexch.PresentationDefinition, purpose string,
		profile *profileapi.Verifier) (*oidc4vp.InteractionInfo, error)
}

type Config struct {
	VerifyCredentialSvc   verifyCredentialSvc
	VerifyPresentationSvc verifyPresentationSvc
	ProfileSvc            profileService
	KMSRegistry           kmsRegistry
	DocumentLoader        ld.DocumentLoader
	VDR                   vdrapi.Registry
	OIDCVPService         oidc4VPService
}

// Controller for Verifier Profile Management API.
type Controller struct {
	verifyCredentialSvc   verifyCredentialSvc
	verifyPresentationSvc verifyPresentationSvc
	profileSvc            profileService
	kmsRegistry           kmsRegistry
	documentLoader        ld.DocumentLoader
	vdr                   vdrapi.Registry
	oidc4VPService        oidc4VPService
}

// NewController creates a new controller for Verifier Profile Management API.
func NewController(config *Config) *Controller {
	return &Controller{
		verifyCredentialSvc:   config.VerifyCredentialSvc,
		verifyPresentationSvc: config.VerifyPresentationSvc,
		profileSvc:            config.ProfileSvc,
		kmsRegistry:           config.KMSRegistry,
		documentLoader:        config.DocumentLoader,
		vdr:                   config.VDR,
		oidc4VPService:        config.OIDCVPService,
	}
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

func (c *Controller) verifyCredential(ctx echo.Context, body *VerifyCredentialData, //nolint:dupl
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

// PostVerifyPresentation Verify presentation.
// (POST /verifier/profiles/{profileID}/presentations/verify).
func (c *Controller) PostVerifyPresentation(ctx echo.Context, profileID string) error {
	var body VerifyPresentationData

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.verifyPresentation(ctx, &body, profileID))
}

func (c *Controller) verifyPresentation(ctx echo.Context, body *VerifyPresentationData, //nolint:dupl
	profileID string) (*VerifyPresentationResponse, error) {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return nil, err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return nil, err
	}

	presentation, err := vp.ValidatePresentation(body.Presentation, profile.Checks.Presentation.Format,
		verifiable.WithPresPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(c.vdr).PublicKeyFetcher(),
		),
		verifiable.WithPresJSONLDDocumentLoader(c.documentLoader))

	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "presentation", err)
	}

	verRes, err := c.verifyPresentationSvc.VerifyPresentation(
		presentation, getVerifyPresentationOptions(body.Options), profile)
	if err != nil {
		return nil, resterr.NewSystemError(verifyCredentialSvcComponent, "VerifyCredential", err)
	}

	return mapVerifyPresentationChecks(verRes), nil
}

func (c *Controller) InitiateOidcInteraction(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	var body InitiateOIDC4VPData

	if err = ctx.Bind(&body); err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "requestBody", err)
	}

	return util.WriteOutput(ctx)(c.initiateOidcInteraction(&body, profile))
}

func (c *Controller) initiateOidcInteraction(data *InitiateOIDC4VPData,
	profile *profileapi.Verifier) (*InitiateOIDC4VPResponse, error) {
	if !profile.Active {
		return nil, resterr.NewValidationError(resterr.ConditionNotMet, "profile.Active",
			errors.New("profile should be active"))
	}

	if profile.OIDCConfig == nil {
		return nil, resterr.NewValidationError(resterr.ConditionNotMet, "profile.OIDCConfig",
			errors.New("OIDC not configured"))
	}

	pd, err := findPresentationDefinition(profile, strPtrToStr(data.PresentationDefinitionId))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "presentationDefinitionID", err)
	}

	result, err := c.oidc4VPService.InitiateOidcInteraction(pd, strPtrToStr(data.Purpose), profile)
	if err != nil {
		return nil, resterr.NewSystemError("oidc4VPService", "InitiateOidcInteraction", err)
	}

	return &InitiateOIDC4VPResponse{
		AuthorizationRequest: result.AuthorizationRequest,
		TxId:                 string(result.TxID),
	}, err
}

func (c *Controller) accessProfile(profileID string, oidcOrgID string) (*profileapi.Verifier, error) {
	profile, err := c.profileSvc.GetProfile(profileID)

	if err != nil {
		if strings.Contains(err.Error(), "data not found") {
			return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
				fmt.Errorf("profile with given id %s, doesn't exist", profileID))
		}

		return nil, resterr.NewSystemError(verifierProfileSvcComponent, "GetProfile", err)
	}

	// Profiles of other organization is not visible.
	if profile.OrganizationID != oidcOrgID {
		return nil, resterr.NewValidationError(resterr.DoesntExist, "organizationID",
			fmt.Errorf("profile with given org id %q, doesn't exist", oidcOrgID))
	}

	return profile, nil
}

func findPresentationDefinition(profile *profileapi.Verifier,
	pdExternalID string) (*presexch.PresentationDefinition, error) {
	pds := profile.PresentationDefinitions

	if pdExternalID == "" && len(pds) > 0 {
		return pds[0], nil
	}

	for _, pd := range pds {
		if pd.ID == pdExternalID {
			return pd, nil
		}
	}
	return nil, fmt.Errorf("presentation definition not found for profile with id=%s", profile.ID)
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

func mapVerifyPresentationChecks(
	checks []verifypresentation.PresentationVerificationCheckResult) *VerifyPresentationResponse {
	if len(checks) == 0 {
		return &VerifyPresentationResponse{}
	}

	var checkList []VerifyPresentationCheckResult
	for _, check := range checks {
		checkList = append(checkList, VerifyPresentationCheckResult{
			Check: check.Check,
			Error: check.Error,
		})
	}

	return &VerifyPresentationResponse{
		Checks: &checkList,
	}
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

func getVerifyPresentationOptions(options *VerifyPresentationOptions) *verifypresentation.Options {
	result := &verifypresentation.Options{}
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

func strPtrToStr(str *string) string {
	if str == nil {
		return ""
	}

	return *str
}
