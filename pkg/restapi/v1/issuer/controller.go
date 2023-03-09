/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package issuer -source=controller.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry,issueCredentialService=MockIssueCredentialService,oidc4ciService=MockOIDC4CIService,vcStatusManager=MockVCStatusManager

package issuer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	util2 "github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
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

type eventService interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type issueCredentialService interface {
	IssueCredential(credential *verifiable.Credential,
		issuerSigningOpts []crypto.SigningOpts,
		profile *profileapi.Issuer) (*verifiable.Credential, error)
}

type oidc4ciService interface {
	InitiateIssuance(
		ctx context.Context,
		req *oidc4ci.InitiateIssuanceRequest,
		profile *profileapi.Issuer,
	) (*oidc4ci.InitiateIssuanceResponse, error)

	PushAuthorizationDetails(
		ctx context.Context,
		opState string,
		ad *oidc4ci.AuthorizationDetails,
	) error

	PrepareClaimDataAuthorizationRequest(
		ctx context.Context,
		req *oidc4ci.PrepareClaimDataAuthorizationRequest,
	) (*oidc4ci.PrepareClaimDataAuthorizationResponse, error)

	StoreAuthorizationCode(
		ctx context.Context,
		opState string,
		code string,
	) (oidc4ci.TxID, error)

	ExchangeAuthorizationCode(
		ctx context.Context,
		opState string,
	) (oidc4ci.TxID, error)

	ValidatePreAuthorizedCodeRequest(
		ctx context.Context,
		preAuthorizedCode string,
		pin string,
	) (*oidc4ci.Transaction, error)

	PrepareCredential(
		ctx context.Context,
		req *oidc4ci.PrepareCredential,
	) (*oidc4ci.PrepareCredentialResult, error)
}

type vcStatusManager interface {
	GetStatusListVC(profileID profileapi.ID, statusID string) (*verifiable.Credential, error)
	UpdateVCStatus(profileID profileapi.ID, vcID, vcStatus string, vcStatusType vc.StatusType) error
}

type Config struct {
	EventSvc               eventService
	ProfileSvc             profileService
	KMSRegistry            kmsRegistry
	DocumentLoader         ld.DocumentLoader
	IssueCredentialService issueCredentialService
	OIDC4CIService         oidc4ciService
	VcStatusManager        vcStatusManager
	ExternalHostURL        string
}

// Controller for Issuer Profile Management API.
type Controller struct {
	profileSvc             profileService
	kmsRegistry            kmsRegistry
	documentLoader         ld.DocumentLoader
	issueCredentialService issueCredentialService
	oidc4ciService         oidc4ciService
	vcStatusManager        vcStatusManager
	externalHostURL        string
}

// NewController creates a new controller for Issuer Profile Management API.
func NewController(config *Config) *Controller {
	return &Controller{
		profileSvc:             config.ProfileSvc,
		kmsRegistry:            config.KMSRegistry,
		documentLoader:         config.DocumentLoader,
		issueCredentialService: config.IssueCredentialService,
		oidc4ciService:         config.OIDC4CIService,
		vcStatusManager:        config.VcStatusManager,
		externalHostURL:        config.ExternalHostURL,
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

func (c *Controller) issueCredential(
	ctx echo.Context,
	body *IssueCredentialData,
	profileID string,
) (*verifiable.Credential, error) {
	tenantID, err := util.GetTenantIDFromRequest(ctx)
	if err != nil {
		return nil, err
	}

	profile, err := c.accessOIDCProfile(profileID, tenantID)
	if err != nil {
		return nil, err
	}

	var finalCredentials interface{}
	var enforceStrictValidation bool

	if body.Credential != nil {
		finalCredentials = *body.Credential
	} else {
		credentialTemplate, tmplErr := c.extractCredentialTemplate(profile, body)
		if tmplErr != nil {
			return nil, tmplErr
		}

		enforceStrictValidation = credentialTemplate.Checks.Strict

		finalCredentials = c.buildCredentialsFromTemplate(credentialTemplate, profile, body)
	}

	credentialParsed, err := c.parseCredential(finalCredentials, enforceStrictValidation, profile.VCConfig.Format)
	if err != nil {
		return nil, err
	}

	credOpts, err := validateIssueCredOptions(body.Options, profile)
	if err != nil {
		return nil, fmt.Errorf("validate validateIssueCredOptions failed: %w", err)
	}

	return c.signCredential(credentialParsed, credOpts, profile)
}

func (c *Controller) extractCredentialTemplate(
	profile *profileapi.Issuer,
	body *IssueCredentialData) (*profileapi.CredentialTemplate, error) {
	if len(profile.CredentialTemplates) == 0 {
		return nil, errors.New("credential templates are not specified for profile")
	}

	if body.Claims == nil || len(*body.Claims) == 0 {
		return nil, errors.New("no claims specified")
	}

	if body.CredentialTemplateId == nil && len(profile.CredentialTemplates) > 1 {
		return nil, errors.New("credential template should be specified")
	}

	var credentialTemplate *profileapi.CredentialTemplate

	if body.CredentialTemplateId != nil {
		for _, template := range profile.CredentialTemplates {
			if strings.EqualFold(template.ID, *body.CredentialTemplateId) {
				credentialTemplate = template
				break
			}
		}

		if credentialTemplate == nil {
			return nil, errors.New("credential template not found")
		}
	}

	credentialTemplate = profile.CredentialTemplates[0]

	return credentialTemplate, nil
}

func (c *Controller) buildCredentialsFromTemplate(
	credentialTemplate *profileapi.CredentialTemplate,
	profile *profileapi.Issuer,
	body *IssueCredentialData,
) *verifiable.Credential {
	vcc := &verifiable.Credential{
		Context: credentialTemplate.Contexts,
		ID:      uuid.New().URN(),
		Types:   []string{"VerifiableCredential", credentialTemplate.Type},
		Issuer:  verifiable.Issuer{ID: profile.SigningDID.DID},
		Subject: verifiable.Subject{
			ID:           profile.SigningDID.DID,
			CustomFields: *body.Claims,
		},
		Issued:       util2.NewTime(time.Now()),
		CustomFields: map[string]interface{}{},
	}

	if lo.FromPtr(body.CredentialDescription) != "" {
		vcc.CustomFields["description"] = *body.CredentialDescription
	}
	if lo.FromPtr(body.CredentialName) != "" {
		vcc.CustomFields["name"] = *body.CredentialName
	}

	if credentialTemplate.CredentialDefaultExpirationDuration != nil {
		vcc.Expired = util2.NewTime(time.Now().UTC().Add(*credentialTemplate.CredentialDefaultExpirationDuration))
	} else {
		vcc.Expired = util2.NewTime(time.Now().Add(365 * 24 * time.Hour))
	}

	return vcc
}

func (c *Controller) parseCredential(cred interface{},
	enforceStrictValidation bool, issuerProfileVCFormat vcsverifiable.Format) (*verifiable.Credential, error) {
	vcSchema := verifiable.JSONSchemaLoader(verifiable.WithDisableRequiredField("issuanceDate"))
	credential, err := vc.ValidateCredential(
		cred,
		[]vcsverifiable.Format{issuerProfileVCFormat},
		false,
		enforceStrictValidation,
		c.documentLoader,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithSchema(vcSchema),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	return credential, nil
}

func (c *Controller) signCredential(
	credential *verifiable.Credential,
	opts []crypto.SigningOpts,
	profile *profileapi.Issuer,
) (*verifiable.Credential, error) {
	signedVC, err := c.issueCredentialService.IssueCredential(credential, opts, profile)
	if err != nil {
		return nil, resterr.NewSystemError("IssueCredentialService", "IssueCredential", err)
	}

	return signedVC, nil
}

func validateIssueCredOptions(
	options *IssueCredentialOptions, profile *profileapi.Issuer) ([]crypto.SigningOpts, error) {
	var signingOpts []crypto.SigningOpts

	if options == nil {
		return signingOpts, nil
	}

	if options.CredentialStatus.Type != "" &&
		options.CredentialStatus.Type != string(profile.VCConfig.Status.Type) {
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

// GetCredentialsStatus retrieves the credentialstatus.CSL.
// GET /issuer/profiles/{profileID}/credentials/status/{statusID}.
func (c *Controller) GetCredentialsStatus(ctx echo.Context, profileID string, statusID string) error {
	return util.WriteOutput(ctx)(c.vcStatusManager.GetStatusListVC(profileID, statusID))
}

// PostCredentialsStatus updates credentialstatus.CSL.
// POST /issuer/profiles/{profileID}/credentials/status.
func (c *Controller) PostCredentialsStatus(ctx echo.Context, profileID string) error {
	var body UpdateCredentialStatusRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	if err := c.vcStatusManager.UpdateVCStatus(
		profileID, body.CredentialID,
		body.CredentialStatus.Status,
		vc.StatusType(body.CredentialStatus.Type),
	); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusOK)
}

// InitiateCredentialIssuance initiates OIDC credential issuance flow.
// POST /issuer/profiles/{profileID}/interactions/initiate-oidc.
func (c *Controller) InitiateCredentialIssuance(ctx echo.Context, profileID string) error {
	tenantID, err := util.GetTenantIDFromRequest(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessOIDCProfile(profileID, tenantID)
	if err != nil {
		return err
	}

	var body InitiateOIDC4CIRequest

	if err = util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.initiateIssuance(ctx.Request().Context(), &body, profile))
}

func (c *Controller) initiateIssuance(
	ctx context.Context,
	req *InitiateOIDC4CIRequest,
	profile *profileapi.Issuer,
) (*InitiateOIDC4CIResponse, error) {
	issuanceReq := &oidc4ci.InitiateIssuanceRequest{
		CredentialTemplateID:      lo.FromPtr(req.CredentialTemplateId),
		ClientInitiateIssuanceURL: lo.FromPtr(req.ClientInitiateIssuanceUrl),
		ClientWellKnownURL:        lo.FromPtr(req.ClientWellknown),
		ClaimEndpoint:             lo.FromPtr(req.ClaimEndpoint),
		GrantType:                 lo.FromPtr(req.GrantType),
		ResponseType:              lo.FromPtr(req.ResponseType),
		Scope:                     lo.FromPtr(req.Scope),
		OpState:                   lo.FromPtr(req.OpState),
		ClaimData:                 lo.FromPtr(req.ClaimData),
		UserPinRequired:           lo.FromPtr(req.UserPinRequired),
		CredentialExpiresAt:       req.CredentialExpiresAt,
		CredentialName:            lo.FromPtr(req.CredentialName),
		CredentialDescription:     lo.FromPtr(req.CredentialDescription),
	}

	resp, err := c.oidc4ciService.InitiateIssuance(ctx, issuanceReq, profile)
	if err != nil {
		if errors.Is(err, oidc4ci.ErrCredentialTemplateNotFound) ||
			errors.Is(err, oidc4ci.ErrCredentialTemplateIDRequired) {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "credential_template_id", err)
		}

		return nil, resterr.NewSystemError("OIDC4CIService", "InitiateIssuance", err)
	}

	return &InitiateOIDC4CIResponse{
		OfferCredentialUrl: resp.InitiateIssuanceURL,
		TxId:               string(resp.TxID),
		UserPin:            lo.ToPtr(resp.UserPin),
	}, nil
}

// PushAuthorizationDetails updates authorization details.
// (POST /issuer/interactions/push-authorization-request).
func (c *Controller) PushAuthorizationDetails(ctx echo.Context) error {
	var body PushAuthorizationDetailsRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	ad, err := common.ValidateAuthorizationDetails(&body.AuthorizationDetails)
	if err != nil {
		return err
	}

	if err = c.oidc4ciService.PushAuthorizationDetails(ctx.Request().Context(), body.OpState, ad); err != nil {
		if errors.Is(err, oidc4ci.ErrCredentialTypeNotSupported) {
			return resterr.NewValidationError(resterr.InvalidValue, "authorization_details.type", err)
		}

		if errors.Is(err, oidc4ci.ErrCredentialFormatNotSupported) {
			return resterr.NewValidationError(resterr.InvalidValue, "authorization_details.format", err)
		}

		return resterr.NewSystemError("OIDC4CIService", "PushAuthorizationRequest", err)
	}

	return ctx.NoContent(http.StatusOK)
}

// PrepareAuthorizationRequest prepares claim data authorization request.
// POST /issuer/interactions/prepare-claim-data-authz-request.
func (c *Controller) PrepareAuthorizationRequest(ctx echo.Context) error {
	var body PrepareClaimDataAuthorizationRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.prepareClaimDataAuthorizationRequest(ctx.Request().Context(), &body))
}

func (c *Controller) prepareClaimDataAuthorizationRequest(
	ctx context.Context,
	body *PrepareClaimDataAuthorizationRequest,
) (*PrepareClaimDataAuthorizationResponse, error) {
	ad, err := common.ValidateAuthorizationDetails(body.AuthorizationDetails)
	if err != nil {
		return nil, err
	}

	resp, err := c.oidc4ciService.PrepareClaimDataAuthorizationRequest(ctx,
		&oidc4ci.PrepareClaimDataAuthorizationRequest{
			ResponseType:         body.ResponseType,
			Scope:                lo.FromPtr(body.Scope),
			OpState:              body.OpState,
			AuthorizationDetails: ad,
		},
	)
	if err != nil {
		return nil, resterr.NewSystemError("OIDC4CIService", "PrepareClaimDataAuthorizationRequest", err)
	}

	profile, err := c.profileSvc.GetProfile(resp.ProfileID)
	if err != nil {
		return nil, resterr.NewSystemError("OIDC4CIService", "PrepareClaimDataAuthorizationRequest", err)
	}

	return &PrepareClaimDataAuthorizationResponse{
		AuthorizationRequest: OAuthParameters{
			ClientId:     profile.OIDCConfig.ClientID,
			ClientSecret: profile.OIDCConfig.ClientSecretHandle,
			ResponseType: resp.ResponseType,
			Scope:        resp.Scope,
		},
		AuthorizationEndpoint:              resp.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: lo.ToPtr(resp.PushedAuthorizationRequestEndpoint),
		TxId:                               string(resp.TxID),
	}, nil
}

func (c *Controller) accessProfile(profileID string) (*profileapi.Issuer, error) {
	profile, err := c.profileSvc.GetProfile(profileID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
				fmt.Errorf("profile with given id %s, doesn't exist", profileID))
		}

		return nil, resterr.NewSystemError(issuerProfileSvcComponent, "GetProfile", err)
	}

	if profile == nil {
		return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
			fmt.Errorf("profile with given id %s, doesn't exist", profileID))
	}

	return profile, nil
}

func (c *Controller) accessOIDCProfile(profileID string, tenantID string) (*profileapi.Issuer, error) {
	profile, err := c.accessProfile(profileID)
	if err != nil {
		return nil, err
	}

	// Profiles of other organization is not visible.
	if profile.OrganizationID != tenantID {
		return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
			fmt.Errorf("profile with given id %s, doesn't exist", profileID))
	}

	return profile, nil
}

// StoreAuthorizationCodeRequest Stores authorization code from issuer oauth provider.
// POST /issuer/interactions/store-authorization-code.
func (c *Controller) StoreAuthorizationCodeRequest(ctx echo.Context) error {
	var body StoreAuthorizationCodeRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.oidc4ciService.StoreAuthorizationCode(ctx.Request().Context(), body.OpState, body.Code))
}

// ExchangeAuthorizationCodeRequest Exchanges authorization code.
// POST /issuer/interactions/exchange-authorization-code.
func (c *Controller) ExchangeAuthorizationCodeRequest(ctx echo.Context) error {
	var body ExchangeAuthorizationCodeRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	txID, err := c.oidc4ciService.ExchangeAuthorizationCode(ctx.Request().Context(), body.OpState)
	if err != nil {
		return util.WriteOutput(ctx)(nil, err)
	}

	return util.WriteOutput(ctx)(ExchangeAuthorizationCodeResponse{TxId: string(txID)}, nil)
}

// ValidatePreAuthorizedCodeRequest Validates authorization code and pin.
// POST /issuer/interactions/validate-pre-authorized-code.
func (c *Controller) ValidatePreAuthorizedCodeRequest(ctx echo.Context) error {
	var body ValidatePreAuthorizedCodeRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	result, err := c.oidc4ciService.ValidatePreAuthorizedCodeRequest(ctx.Request().Context(),
		body.PreAuthorizedCode, lo.FromPtr(body.UserPin))

	if err != nil {
		return err
	}

	return util.WriteOutput(ctx)(ValidatePreAuthorizedCodeResponse{
		TxId:    string(result.ID),
		OpState: result.OpState,
		Scopes:  result.Scope,
	}, nil)
}

// PrepareCredential requests claim data and prepares VC for signing by issuer.
// POST /issuer/interactions/prepare-credential.
func (c *Controller) PrepareCredential(ctx echo.Context) error {
	var body PrepareCredential

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	vcFormat, err := common.ValidateVCFormat(common.VCFormat(lo.FromPtr(body.Format)))
	if err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "format", err)
	}

	result, err := c.oidc4ciService.PrepareCredential(
		ctx.Request().Context(),
		&oidc4ci.PrepareCredential{
			TxID:             oidc4ci.TxID(body.TxId),
			CredentialTypes:  body.Types,
			CredentialFormat: vcFormat,
			DID:              lo.FromPtr(body.Did),
		},
	)

	if err != nil {
		var custom *resterr.CustomError
		if errors.As(err, &custom) {
			return custom
		}

		return resterr.NewSystemError("OIDC4CIService", "PrepareCredential", err)
	}

	profile, err := c.accessProfile(result.ProfileID)
	if err != nil {
		return err
	}

	credentialParsed, err := c.parseCredential(
		result.Credential, result.EnforceStrictValidation, profile.VCConfig.Format)
	if err != nil {
		return err
	}

	signedCredential, err := c.signCredential(credentialParsed, nil, profile)
	if err != nil {
		return err
	}

	return util.WriteOutput(ctx)(PrepareCredentialResult{
		Credential: signedCredential,
		Format:     string(result.Format),
		OidcFormat: string(result.OidcFormat),
		Retry:      result.Retry,
	}, nil)
}

// OpenidConfig request openid configuration for issuer.
// GET /issuer/{profileID}/.well-known/openid-configuration.
func (c *Controller) OpenidConfig(ctx echo.Context, profileID string) error {
	return util.WriteOutput(ctx)(c.getOpenIDConfig(profileID))
}

// OpenidCredentialIssuerConfig request openid credentials configuration for issuer.
// GET /issuer/{profileID}/.well-known/openid-credential-issuer.
func (c *Controller) OpenidCredentialIssuerConfig(ctx echo.Context, profileID string) error {
	return util.WriteOutput(ctx)(c.getOpenIDIssuerConfig(profileID))
}

func (c *Controller) getOpenIDIssuerConfig(profileID string) (*WellKnownOpenIDIssuerConfiguration, error) {
	host := c.externalHostURL
	if !strings.HasSuffix(host, "/") {
		host += "/"
	}

	issuer, err := c.profileSvc.GetProfile(profileID)
	if err != nil {
		return nil, err
	}

	var finalCredentials []interface{}
	for _, t := range issuer.CredentialMetaData.CredentialsSupported {
		if issuer.VCConfig != nil {
			t["cryptographic_binding_methods_supported"] = []string{string(issuer.VCConfig.DIDMethod)}
			t["cryptographic_suites_supported"] = []string{string(issuer.VCConfig.KeyType)}
		}
		finalCredentials = append(finalCredentials, t)
	}

	issuerURL, _ := url.JoinPath(c.externalHostURL, "issuer", profileID)

	final := &WellKnownOpenIDIssuerConfiguration{
		AuthorizationServer:     fmt.Sprintf("%soidc/authorize", host), // todo check
		BatchCredentialEndpoint: nil,                                   // no support for now
		CredentialEndpoint:      fmt.Sprintf("%soidc/credential", host),
		CredentialsSupported:    finalCredentials,
		CredentialIssuer:        issuerURL,
		Display: lo.ToPtr([]CredentialDisplay{
			{
				Locale: lo.ToPtr("en-US"),
				Name:   lo.ToPtr(issuer.Name),
			},
		}),
	}

	return final, nil
}

func (c *Controller) getOpenIDConfig(profileID string) (*WellKnownOpenIDConfiguration, error) {
	host := c.externalHostURL
	if !strings.HasSuffix(host, "/") {
		host += "/"
	}

	_, err := c.profileSvc.GetProfile(profileID) // no need currently
	if err != nil {
		return nil, err
	}

	return &WellKnownOpenIDConfiguration{
		AuthorizationEndpoint: fmt.Sprintf("%soidc/authorize", host),
		ResponseTypesSupported: []string{
			"code",
		},
		TokenEndpoint: fmt.Sprintf("%soidc/token", host),
	}, nil
}
