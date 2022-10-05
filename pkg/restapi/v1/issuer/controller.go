/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package issuer -source=controller.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry,issueCredentialService=MockIssueCredentialService,oidc4VCService=MockOIDC4VCService

package issuer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	cslstatus "github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

const (
	issuerProfileSvcComponent = "issuer.ProfileService"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type kmsManager = kms.VCSKeyManager

type kmsRegistry interface {
	GetKeyManager(config *kms.Config) (kmsManager, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error)
}

type issueCredentialService interface {
	IssueCredential(credential *verifiable.Credential,
		issuerSigningOpts []crypto.SigningOpts,
		profile *profileapi.Issuer) (*verifiable.Credential, error)
}

type oidc4VCService interface {
	InitiateOIDCInteraction(req *oidc4vc.InitiateIssuanceRequest) (*oidc4vc.InitiateIssuanceInfo, error)
}

type Config struct {
	ProfileSvc             profileService
	KMSRegistry            kmsRegistry
	DocumentLoader         ld.DocumentLoader
	IssueCredentialService issueCredentialService
	OIDC4VCService         oidc4VCService
}

// Controller for Issuer Profile Management API.
type Controller struct {
	profileSvc             profileService
	kmsRegistry            kmsRegistry
	documentLoader         ld.DocumentLoader
	issueCredentialService issueCredentialService
	oidc4VCService         oidc4VCService
}

// NewController creates a new controller for Issuer Profile Management API.
func NewController(config *Config) *Controller {
	return &Controller{
		profileSvc:             config.ProfileSvc,
		kmsRegistry:            config.KMSRegistry,
		documentLoader:         config.DocumentLoader,
		issueCredentialService: config.IssueCredentialService,
		oidc4VCService:         config.OIDC4VCService,
	}
}

// PostIssueCredentials issues credentials.
// POST /issuer/profiles/{profileID}/credentials/issue.
func (c *Controller) PostIssueCredentials(ctx echo.Context, profileID string) error {
	var body IssueCredentialData

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.issueCredential(ctx, &body, profileID))
}

func (c *Controller) issueCredential(ctx echo.Context, body *IssueCredentialData,
	profileID string) (*verifiable.Credential, error) {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return nil, err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return nil, err
	}

	vcSchema := verifiable.JSONSchemaLoader(verifiable.WithDisableRequiredField("issuanceDate"))

	credential, err := vc.ValidateCredential(body.Credential, []vcsverifiable.Format{profile.VCConfig.Format},
		verifiable.WithDisabledProofCheck(),
		verifiable.WithSchema(vcSchema),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	credOpts, err := validateIssueCredOptions(body.Options)
	if err != nil {
		return nil, err
	}

	signedVC, err := c.issueCredentialService.IssueCredential(credential, credOpts, profile)
	if err != nil {
		return nil, resterr.NewSystemError("IssueCredentialService", "IssueCredential", err)
	}

	return signedVC, nil
}

func validateIssueCredOptions(options *IssueCredentialOptions) ([]crypto.SigningOpts, error) {
	var signingOpts []crypto.SigningOpts

	if options == nil {
		return signingOpts, nil
	}
	if options.CredentialStatus.Type != "" && options.CredentialStatus.Type != cslstatus.StatusList2021Entry {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "options.credentialStatus",
			fmt.Errorf("not supported credential status type : %s", options.CredentialStatus.Type))
	}

	verificationMethod := options.VerificationMethod

	if verificationMethod != nil {
		signingOpts = append(signingOpts, crypto.WithVerificationMethod(*verificationMethod))
	}

	if options.Created != nil {
		created, err := time.Parse(time.RFC3339, *options.Created)
		if err != nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "options.created", err)
		}
		signingOpts = append(signingOpts, crypto.WithCreated(&created))
	}

	if options.Challenge != nil {
		signingOpts = append(signingOpts, crypto.WithChallenge(*options.Challenge))
	}

	if options.Domain != nil {
		signingOpts = append(signingOpts, crypto.WithDomain(*options.Domain))
	}

	return signingOpts, nil
}

// PostIssuerProfilesProfileIDInteractionsInitiateOidc initiates OIDC Credential Issuance.
// POST /issuer/profiles/{profileID}/interactions/initiate-oidc.
func (c *Controller) PostIssuerProfilesProfileIDInteractionsInitiateOidc(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	var body InitiateOIDC4VCRequest

	if err = util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.initiateOidcInteraction(&body, profile))
}

func (c *Controller) initiateOidcInteraction(body *InitiateOIDC4VCRequest,
	profile *profileapi.Issuer) (*InitiateOIDC4VCResponse, error) {
	if !profile.Active {
		return nil, resterr.NewValidationError(resterr.ConditionNotMet, "profile.Active",
			errors.New("profile should be active"))
	}

	if profile.OIDCConfig == nil {
		return nil, resterr.NewValidationError(resterr.ConditionNotMet, "profile.OIDCConfig",
			errors.New("OIDC not configured"))
	}

	template, err := findCredentialTemplate(profile.CredentialTemplates, lo.FromPtr(body.CredentialTemplateId))
	if err != nil {
		return nil, err
	}

	issuanceReq := &oidc4vc.InitiateIssuanceRequest{
		CredentialTemplate:        template,
		ClientInitiateIssuanceURL: lo.FromPtr(body.ClientInitiateIssuanceUrl),
		ClientWellKnownURL:        lo.FromPtr(body.ClientWellknown),
		ClaimEndpoint:             lo.FromPtr(body.ClaimEndpoint),
		GrantType:                 lo.FromPtr(body.GrantType),
		ResponseType:              lo.FromPtr(body.ResponseType),
		Scope:                     lo.FromPtr(body.Scope),
		OpState:                   lo.FromPtr(body.OpState),
	}

	info, err := c.oidc4VCService.InitiateOIDCInteraction(issuanceReq)
	if err != nil {
		return nil, resterr.NewSystemError("OIDC4VCService", "InitiateOIDCInteraction", err)
	}

	return &InitiateOIDC4VCResponse{
		InitiateIssuanceUrl: info.InitiateIssuanceURL,
		TxId:                info.TxID,
	}, nil
}

func findCredentialTemplate(credentialTemplates []*verifiable.Credential, templateID string) (
	*verifiable.Credential, error) {
	// profile should define at least one credential template
	if len(credentialTemplates) == 0 || credentialTemplates[0].ID == "" {
		return nil, resterr.NewValidationError(resterr.ConditionNotMet, "profile.CredentialTemplates",
			errors.New("credential template not configured"))
	}

	// credential_template_id param is required if profile has more than one credential template defined
	if len(credentialTemplates) > 1 && templateID == "" {
		return nil, resterr.NewValidationError(resterr.ConditionNotMet, "credential_template_id",
			errors.New("credential template id is required"))
	}

	for _, t := range credentialTemplates {
		if t.ID == templateID {
			return t, nil
		}
	}

	return nil, resterr.NewValidationError(resterr.ConditionNotMet, "credential_template_id",
		errors.New("credential template not found"))
}

func (c *Controller) accessProfile(profileID string, oidcOrgID string) (*profileapi.Issuer, error) {
	profile, err := c.profileSvc.GetProfile(profileID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
				fmt.Errorf("profile with given id %s, dosn't exists", profileID))
		}

		return nil, resterr.NewSystemError(issuerProfileSvcComponent, "GetProfile", err)
	}

	// Profiles of other organization is not visible.
	if profile.OrganizationID != oidcOrgID {
		return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
			fmt.Errorf("profile with given id %s, dosn't exists", profileID))
	}

	return profile, nil
}
