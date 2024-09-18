/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package github.com/trustbloc/vcs/pkg/restapi/v1/issuer -package issuer -source=controller.go -mock_names profileService=MockProfileService,issueCredentialService=MockIssueCredentialService,oidc4ciService=MockOIDC4CIService,vcStatusManager=MockVCStatusManager,openidCredentialIssuerConfigProvider=MockOpenIDCredentialIssuerConfigProvider,eventService=MockEventService,jsonSchemaValidator=MockJSONSchemaValidator,credentialIssuanceHistoryStore=MockCredentialIssuanceHistoryStore

package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/trustbloc/did-go/doc/ld/validator"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/refresh"
)

var logger = log.New("restapi-issuer")

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error)
}

type eventService interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type issueCredentialService interface {
	issuecredential.ServiceInterface
}

type oidc4ciService interface {
	oidc4ci.ServiceInterface
}

type vcStatusManager interface {
	credentialstatus.ServiceInterface
}

type openidCredentialIssuerConfigProvider interface {
	GetOpenIDCredentialIssuerConfig(issuerProfile *profileapi.Issuer) (*WellKnownOpenIDIssuerConfiguration, string, error)
}

type credentialIssuanceHistoryStore interface {
	GetIssuedCredentialsMetadata(
		ctx context.Context,
		profileID string,
		txID *string,
		credentialID *string,
	) ([]*credentialstatus.CredentialMetadata, error)
}

type jsonSchemaValidator interface {
	Validate(data interface{}, schemaID string, schema []byte) error
}

type CredentialRefreshService interface {
	CreateRefreshState(
		ctx context.Context,
		req *refresh.CreateRefreshStateRequest,
	) (string, error)
}

type Config struct {
	EventSvc                       eventService
	EventTopic                     string
	ProfileSvc                     profileService
	DocumentLoader                 ld.DocumentLoader
	IssueCredentialService         issuecredential.ServiceInterface
	OIDC4CIService                 oidc4ciService
	VcStatusManager                vcStatusManager
	OpenidIssuerConfigProvider     openidCredentialIssuerConfigProvider
	CredentialIssuanceHistoryStore credentialIssuanceHistoryStore
	ExternalHostURL                string
	Tracer                         trace.Tracer
	JSONSchemaValidator            jsonSchemaValidator
	CredentialRefreshService       CredentialRefreshService
}

// Controller for Issuer Profile Management API.
type Controller struct {
	profileSvc                     profileService
	documentLoader                 ld.DocumentLoader
	issueCredentialService         issuecredential.ServiceInterface
	oidc4ciService                 oidc4ciService
	vcStatusManager                vcStatusManager
	openidIssuerConfigProvider     openidCredentialIssuerConfigProvider
	credentialIssuanceHistoryStore credentialIssuanceHistoryStore
	externalHostURL                string
	tracer                         trace.Tracer
	schemaValidator                jsonSchemaValidator
	eventSvc                       eventService
	eventTopic                     string
	marshal                        func(any) ([]byte, error)
	credentialRefreshService       CredentialRefreshService
}

// NewController creates a new controller for Issuer Profile Management API.
func NewController(config *Config) *Controller {
	return &Controller{
		profileSvc:                     config.ProfileSvc,
		documentLoader:                 config.DocumentLoader,
		issueCredentialService:         config.IssueCredentialService,
		oidc4ciService:                 config.OIDC4CIService,
		vcStatusManager:                config.VcStatusManager,
		openidIssuerConfigProvider:     config.OpenidIssuerConfigProvider,
		credentialIssuanceHistoryStore: config.CredentialIssuanceHistoryStore,
		externalHostURL:                config.ExternalHostURL,
		tracer:                         config.Tracer,
		schemaValidator:                config.JSONSchemaValidator,
		eventSvc:                       config.EventSvc,
		eventTopic:                     config.EventTopic,
		marshal:                        json.Marshal,
		credentialRefreshService:       config.CredentialRefreshService,
	}
}

// SetCredentialRefreshState sets claims for credential refresh.
// POST /issuer/profiles/{profileID}/{profileVersion}/interactions/refresh.
func (c *Controller) SetCredentialRefreshState(ctx echo.Context, profileID string, profileVersion string) error {
	var body SetCredentialRefreshStateRequest
	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	profile, err := c.profileSvc.GetProfile(profileID, profileVersion)
	if err != nil {
		return resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent,
			"PrepareClaimDataAuthorizationRequest", err)
	}

	txID, err := c.credentialRefreshService.CreateRefreshState(ctx.Request().Context(), &refresh.CreateRefreshStateRequest{
		CredentialID:          body.CredentialId,
		Issuer:                *profile,
		Claims:                body.Claims,
		CredentialName:        body.CredentialName,
		CredentialDescription: body.CredentialDescription,
	})
	if err != nil {
		return resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "SetCredentialRefreshState", err)
	}

	return util.WriteOutput(ctx)(SetCredentialRefreshStateResult{
		TransactionId: txID,
	}, nil)
}

// PostIssueCredentials issues credentials.
// POST /issuer/profiles/{profileID}/{profileVersion}/credentials/issue.
func (c *Controller) PostIssueCredentials(e echo.Context, profileID, profileVersion string) error {
	ctx, span := c.tracer.Start(e.Request().Context(), "PostIssueCredentials")
	defer span.End()

	var body IssueCredentialData

	if err := util.ReadBody(e, &body); err != nil {
		return err
	}

	tenantID, err := util.GetTenantIDFromRequest(e)
	if err != nil {
		return err
	}

	span.SetAttributes(attribute.String("profile_id", profileID))

	credential, err := c.issueCredential(ctx, tenantID, &body, profileID, profileVersion)
	if err != nil {
		return err
	}

	return util.WriteOutput(e)(credential, nil)
}

func (c *Controller) issueCredential(
	ctx context.Context,
	tenantID string,
	body *IssueCredentialData,
	profileID string,
	profileVersion string,
) (*verifiable.Credential, error) {
	profile, err := c.accessOIDCProfile(profileID, profileVersion, tenantID)
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

		finalCredentials, err = c.buildCredentialsFromTemplate(credentialTemplate, profile, body)
		if err != nil {
			return nil, err
		}
	}

	credentialParsed, err := c.parseCredential(ctx, finalCredentials, enforceStrictValidation, profile.VCConfig)
	if err != nil {
		return nil, err
	}

	credOpts, err := validateIssueCredOptions(body.Options, profile)
	if err != nil {
		return nil, fmt.Errorf("validate validateIssueCredOptions failed: %w", err)
	}

	return c.signCredential(ctx, credentialParsed, profile, issuecredential.WithCryptoOpts(credOpts))
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
) (*verifiable.Credential, error) {
	contexts := credentialTemplate.Contexts
	if len(contexts) == 0 {
		baseContext, err := getBaseContext(profile.VCConfig)
		if err != nil {
			return nil, err
		}

		contexts = []string{baseContext}
	} else if err := validateBaseContext(contexts, profile.VCConfig); err != nil {
		return nil, err
	}

	vcc := verifiable.CredentialContents{
		Context: contexts,
		ID:      uuid.New().URN(),
		Types:   []string{"VerifiableCredential", credentialTemplate.Type},
		Issuer:  &verifiable.Issuer{ID: profile.SigningDID.DID},
		Subject: []verifiable.Subject{{
			ID:           profile.SigningDID.DID,
			CustomFields: *body.Claims,
		}},
		Issued: utiltime.NewTime(time.Now()),
	}

	customFields := map[string]interface{}{}

	if lo.FromPtr(body.CredentialDescription) != "" {
		customFields["description"] = *body.CredentialDescription
	}
	if lo.FromPtr(body.CredentialName) != "" {
		customFields["name"] = *body.CredentialName
	}

	if credentialTemplate.CredentialDefaultExpirationDuration != nil {
		vcc.Expired = utiltime.NewTime(time.Now().UTC().Add(*credentialTemplate.CredentialDefaultExpirationDuration))
	} else {
		vcc.Expired = utiltime.NewTime(time.Now().Add(365 * 24 * time.Hour))
	}

	return verifiable.CreateCredential(vcc, customFields)
}

func (c *Controller) parseCredential(
	ctx context.Context,
	cred interface{},
	enforceStrictValidation bool,
	config *profileapi.VCConfig,
) (*verifiable.Credential, error) {
	schema, err := getJSONSchema(config)
	if err != nil {
		return nil, err
	}

	credential, err := vc.ValidateCredential(
		ctx,
		cred,
		[]vcsverifiable.Format{config.Format},
		false,
		enforceStrictValidation,
		c.documentLoader,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithSchema(schema),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	return credential, nil
}

func (c *Controller) signCredential(
	ctx context.Context,
	credential *verifiable.Credential,
	profile *profileapi.Issuer,
	opts ...issuecredential.Opts,
) (*verifiable.Credential, error) {
	signedVC, err := c.issueCredentialService.IssueCredential(ctx, credential, profile, opts...)
	if err != nil {
		return nil, resterr.NewSystemError(resterr.IssueCredentialSvcComponent, "IssueCredential", err)
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
// GET /issuer/groups/{groupID}/credentials/status/{statusID}.
func (c *Controller) GetCredentialsStatus(ctx echo.Context, groupID string, statusID string) error {
	return util.WriteOutput(ctx)(c.vcStatusManager.GetStatusListVC(ctx.Request().Context(), groupID, statusID))
}

// PostCredentialsStatus updates credentialstatus.CSL.
// POST /issuer/credentials/status.
func (c *Controller) PostCredentialsStatus(ctx echo.Context) error {
	var body UpdateCredentialStatusRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	if err := c.vcStatusManager.UpdateVCStatus(
		ctx.Request().Context(),
		credentialstatus.UpdateVCStatusParams{
			ProfileID:      body.ProfileID,
			ProfileVersion: body.ProfileVersion,
			CredentialID:   body.CredentialID,
			DesiredStatus:  body.CredentialStatus.Status,
			StatusType:     vc.StatusType(body.CredentialStatus.Type),
		},
	); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusOK)
}

// InitiateCredentialComposeIssuance initiates OIDC credential issuance flow.
// POST /issuer/profiles/{profileID}/{profileVersion}/interactions/compose-and-initiate-issuance.
func (c *Controller) InitiateCredentialComposeIssuance(e echo.Context, profileID string, profileVersion string) error {
	ctx, span := c.tracer.Start(e.Request().Context(), "InitiateCredentialComposeIssuance")
	defer span.End()

	tenantID, err := util.GetTenantIDFromRequest(e)
	if err != nil {
		// Don't send a failed event since we have no context for the event, i,e, no tenant ID, etc.
		return err
	}

	span.SetAttributes(attribute.String("profile_id", profileID))

	profile, err := c.accessOIDCProfile(profileID, profileVersion, tenantID)
	if err != nil {
		c.sendFailedEvent(ctx, tenantID, profileID, profileVersion, err)

		return err
	}

	var body InitiateOIDC4CIComposeRequest

	if err = util.ReadBody(e, &body); err != nil {
		c.sendFailedEvent(ctx, tenantID, profileID, profileVersion, err)

		return err
	}

	var configs []InitiateIssuanceCredentialConfiguration

	for _, compose := range lo.FromPtr(body.Compose) {
		configs = append(configs, InitiateIssuanceCredentialConfiguration{
			Compose: &DeprecatedComposeOIDC4CICredential{
				Credential:              compose.Credential,
				IdTemplate:              compose.CredentialOverrideId,
				OverrideIssuer:          compose.CredentialOverrideIssuer,
				OverrideSubjectDid:      compose.CredentialOverrideSubjectDid,
				PerformStrictValidation: compose.CredentialPerformStrictValidation,
			},
			CredentialExpiresAt: compose.CredentialExpiresAt,
		})
	}

	mapped := InitiateOIDC4CIRequest{
		AuthorizationDetails:      body.AuthorizationDetails,
		ClientInitiateIssuanceUrl: body.ClientInitiateIssuanceUrl,
		ClientWellknown:           body.ClientWellknown,
		CredentialConfiguration:   &configs,
		OpState:                   body.OpState,
		ResponseType:              body.ResponseType,
		Scope:                     body.Scope,
		UserPinRequired:           body.UserPinRequired,
		WalletInitiatedIssuance:   body.WalletInitiatedIssuance,
	}

	if body.GrantType != nil {
		mapped.GrantType = lo.ToPtr(InitiateOIDC4CIRequestGrantType(*body.GrantType))
	}

	resp, ct, err := c.initiateIssuance(ctx, &mapped, profile)
	if err != nil {
		return err
	}

	return util.WriteOutputWithContentType(e)(resp, ct, nil)
}

// InitiateCredentialIssuance initiates OIDC credential issuance flow.
// POST /issuer/profiles/{profileID}/{profileVersion}/interactions/initiate-oidc.
func (c *Controller) InitiateCredentialIssuance(e echo.Context, profileID, profileVersion string) error {
	ctx, span := c.tracer.Start(e.Request().Context(), "InitiateCredentialIssuance")
	defer span.End()

	tenantID, err := util.GetTenantIDFromRequest(e)
	if err != nil {
		// Don't send a failed event since we have no context for the event, i,e, no tenant ID, etc.
		return err
	}

	span.SetAttributes(attribute.String("profile_id", profileID))

	profile, err := c.accessOIDCProfile(profileID, profileVersion, tenantID)
	if err != nil {
		c.sendFailedEvent(ctx, tenantID, profileID, profileVersion, err)

		return err
	}

	var body InitiateOIDC4CIRequest

	if err = util.ReadBody(e, &body); err != nil {
		c.sendFailedEvent(ctx, tenantID, profileID, profileVersion, err)

		return err
	}

	resp, ct, err := c.initiateIssuance(ctx, &body, profile)
	if err != nil {
		return err
	}

	return util.WriteOutputWithContentType(e)(resp, ct, nil)
}

func (c *Controller) initiateIssuance(
	ctx context.Context,
	req *InitiateOIDC4CIRequest,
	profile *profileapi.Issuer,
) (*InitiateOIDC4CIResponse, string, error) {
	issuanceReq := &oidc4ci.InitiateIssuanceRequest{
		ClientInitiateIssuanceURL: lo.FromPtr(req.ClientInitiateIssuanceUrl),
		ClientWellKnownURL:        lo.FromPtr(req.ClientWellknown),
		GrantType:                 string(lo.FromPtr(req.GrantType)),
		ResponseType:              lo.FromPtr(req.ResponseType),
		Scope:                     lo.FromPtr(req.Scope),
		OpState:                   lo.FromPtr(req.OpState),
		UserPinRequired:           lo.FromPtr(req.UserPinRequired),
		WalletInitiatedIssuance:   lo.FromPtr(req.WalletInitiatedIssuance),
		CredentialConfiguration:   []oidc4ci.InitiateIssuanceCredentialConfiguration{},
	}

	for _, multiCredentialIssuance := range lo.FromPtr(req.CredentialConfiguration) {
		credConfig := oidc4ci.InitiateIssuanceCredentialConfiguration{
			ClaimData:             lo.FromPtr(multiCredentialIssuance.ClaimData),
			ClaimEndpoint:         lo.FromPtr(multiCredentialIssuance.ClaimEndpoint),
			CredentialTemplateID:  lo.FromPtr(multiCredentialIssuance.CredentialTemplateId),
			CredentialExpiresAt:   multiCredentialIssuance.CredentialExpiresAt,
			CredentialName:        lo.FromPtr(multiCredentialIssuance.CredentialName),
			CredentialDescription: lo.FromPtr(multiCredentialIssuance.CredentialDescription),
		}

		if multiCredentialIssuance.Compose != nil {
			credConfig.ComposeCredential = &oidc4ci.InitiateIssuanceComposeCredential{
				Credential:              multiCredentialIssuance.Compose.Credential,
				IDTemplate:              lo.FromPtr(multiCredentialIssuance.Compose.IdTemplate),
				OverrideIssuer:          lo.FromPtr(multiCredentialIssuance.Compose.OverrideIssuer),
				OverrideSubjectDID:      lo.FromPtr(multiCredentialIssuance.Compose.OverrideSubjectDid),
				PerformStrictValidation: lo.FromPtr(multiCredentialIssuance.Compose.PerformStrictValidation),
			}
		}

		issuanceReq.CredentialConfiguration = append(issuanceReq.CredentialConfiguration, credConfig)
	}

	if len(issuanceReq.CredentialConfiguration) == 0 { // legacy compatibility
		issuanceReq.CredentialConfiguration = append(issuanceReq.CredentialConfiguration,
			oidc4ci.InitiateIssuanceCredentialConfiguration{
				ClaimData:             lo.FromPtr(req.ClaimData),
				ClaimEndpoint:         lo.FromPtr(req.ClaimEndpoint),
				CredentialTemplateID:  lo.FromPtr(req.CredentialTemplateId),
				CredentialExpiresAt:   req.CredentialExpiresAt,
				CredentialName:        lo.FromPtr(req.CredentialName),
				CredentialDescription: lo.FromPtr(req.CredentialDescription),
			})
	}

	resp, err := c.oidc4ciService.InitiateIssuance(ctx, issuanceReq, profile)
	if err != nil {
		if errors.Is(err, resterr.ErrCredentialTemplateNotFound) ||
			errors.Is(err, resterr.ErrCredentialTemplateIDRequired) {
			c.sendFailedEvent(ctx, profile.OrganizationID, profile.ID, profile.Version, err)

			return nil, "", err
		}

		var ce *resterr.CustomError
		if ok := errors.As(err, &ce); ok {
			c.sendFailedEvent(ctx, profile.OrganizationID, profile.ID, profile.Version, err)

			return nil, "", err
		}

		e := resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "InitiateIssuance", err)

		c.sendFailedEvent(ctx, profile.OrganizationID, profile.ID, profile.Version, e)

		return nil, "", e
	}

	return &InitiateOIDC4CIResponse{
		OfferCredentialUrl: resp.InitiateIssuanceURL,
		TxId:               string(resp.TxID),
		UserPin:            lo.ToPtr(resp.UserPin),
	}, resp.ContentType, nil
}

// PushAuthorizationDetails updates authorization details.
// (POST /issuer/interactions/push-authorization-request).
func (c *Controller) PushAuthorizationDetails(ctx echo.Context) error {
	var body PushAuthorizationDetailsRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	ad, err := util.ValidateAuthorizationDetails(body.AuthorizationDetails)
	if err != nil {
		return err
	}

	if err = c.oidc4ciService.PushAuthorizationDetails(ctx.Request().Context(), body.OpState, ad); err != nil {
		if errors.Is(err, resterr.ErrCredentialTypeNotSupported) {
			return resterr.NewValidationError(resterr.InvalidValue, "authorization_details.type", err)
		}

		if errors.Is(err, resterr.ErrCredentialFormatNotSupported) {
			return resterr.NewValidationError(resterr.InvalidValue, "authorization_details.format", err)
		}

		if errors.Is(err, resterr.ErrInvalidCredentialConfigurationID) {
			return resterr.NewValidationError(resterr.InvalidValue, "authorization_details.credential_configuration_id", err)
		}

		return resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "PushAuthorizationRequest", err)
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
	var (
		ad  []*issuecredential.AuthorizationDetails
		err error
	)

	if body.AuthorizationDetails != nil {
		ad, err = util.ValidateAuthorizationDetails(*body.AuthorizationDetails)
		if err != nil {
			return nil, err
		}
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
		return nil, resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "PrepareClaimDataAuthorizationRequest", err)
	}

	profile, err := c.profileSvc.GetProfile(resp.ProfileID, resp.ProfileVersion)
	if err != nil {
		return nil, resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "PrepareClaimDataAuthorizationRequest", err)
	}

	return &PrepareClaimDataAuthorizationResponse{
		WalletInitiatedFlow: resp.WalletInitiatedFlow,
		AuthorizationRequest: OAuthParameters{
			ClientId:     profile.OIDCConfig.ClientID,
			ClientSecret: profile.OIDCConfig.ClientSecretHandle,
			Scope:        resp.Scope,
			ResponseType: resp.ResponseType,
		},
		AuthorizationEndpoint:              resp.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: lo.ToPtr(resp.PushedAuthorizationRequestEndpoint),
		TxId:                               string(resp.TxID),
		ProfileAuthStateTtl:                int(profile.DataConfig.OIDC4CIAuthStateTTL),
	}, nil
}

func (c *Controller) accessProfile(profileID, profileVersion string) (*profileapi.Issuer, error) {
	profile, err := c.profileSvc.GetProfile(profileID, profileVersion)
	if err != nil {
		if errors.Is(err, resterr.ErrProfileNotFound) {
			return nil, resterr.NewCustomError(resterr.ProfileNotFound,
				fmt.Errorf("profile with given id %s_%s, doesn't exist", profileID, profileVersion))
		}

		return nil, resterr.NewSystemError(resterr.IssuerProfileSvcComponent, "GetProfile", err)
	}

	if profile == nil {
		logger.Debug("Received null profile from profile service", log.WithError(err),
			logfields.WithProfileID(profileID), logfields.WithProfileVersion(profileVersion))

		return nil, resterr.NewCustomError(resterr.ProfileNotFound,
			fmt.Errorf("profile with given id %s_%s, doesn't exist", profileID, profileVersion))
	}

	return profile, nil
}

func (c *Controller) accessOIDCProfile(profileID, profileVersion, tenantID string) (*profileapi.Issuer, error) {
	profile, err := c.accessProfile(profileID, profileVersion)
	if err != nil {
		return nil, err
	}

	// Profiles of other organization is not visible.
	if profile.OrganizationID != tenantID {
		logger.Debug("Profile's owning org does not match the current tenant ID",
			logfields.WithProfileID(profileID), logfields.WithProfileVersion(profileVersion))

		return nil, resterr.NewCustomError(resterr.ProfileNotFound,
			fmt.Errorf("profile with given id %s_%s, doesn't exist", profileID, profileVersion))
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

	return util.WriteOutput(ctx)(c.oidc4ciService.StoreAuthorizationCode(ctx.Request().Context(),
		body.OpState, body.Code, body.WalletInitiatedFlow))
}

// ExchangeAuthorizationCodeRequest Exchanges authorization code.
// POST /issuer/interactions/exchange-authorization-code.
func (c *Controller) ExchangeAuthorizationCodeRequest(ctx echo.Context) error {
	var body ExchangeAuthorizationCodeRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	exchangeAuthorizationCodeResult, err := c.oidc4ciService.ExchangeAuthorizationCode(ctx.Request().Context(),
		body.OpState,
		lo.FromPtr(body.ClientId),
		lo.FromPtr(body.ClientAssertionType),
		lo.FromPtr(body.ClientAssertion),
	)
	if err != nil {
		return util.WriteOutput(ctx)(nil, err)
	}

	var authorizationDetailsDTOList []common.AuthorizationDetails
	for _, ad := range exchangeAuthorizationCodeResult.AuthorizationDetails {
		authorizationDetailsDTOList = append(authorizationDetailsDTOList, ad.ToDTO())
	}

	return util.WriteOutput(ctx)(
		ExchangeAuthorizationCodeResponse{
			AuthorizationDetails: lo.ToPtr(authorizationDetailsDTOList),
			TxId:                 string(exchangeAuthorizationCodeResult.TxID),
		}, nil)
}

// ValidatePreAuthorizedCodeRequest Validates authorization code and pin.
// POST /issuer/interactions/validate-pre-authorized-code.
func (c *Controller) ValidatePreAuthorizedCodeRequest(ctx echo.Context) error {
	var body ValidatePreAuthorizedCodeRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	transaction, err := c.oidc4ciService.ValidatePreAuthorizedCodeRequest(ctx.Request().Context(),
		body.PreAuthorizedCode,
		lo.FromPtr(body.UserPin),
		lo.FromPtr(body.ClientId),
		lo.FromPtr(body.ClientAssertionType),
		lo.FromPtr(body.ClientAssertion),
	)
	if err != nil {
		return err
	}

	var authorizationDetailsDTOList []common.AuthorizationDetails

	for _, credentialConfig := range transaction.CredentialConfiguration {
		if credentialConfig.AuthorizationDetails != nil {
			authorizationDetailsDTOList = append(authorizationDetailsDTOList, credentialConfig.AuthorizationDetails.ToDTO())
		}
	}

	return util.WriteOutput(ctx)(ValidatePreAuthorizedCodeResponse{
		AuthorizationDetails: lo.ToPtr(authorizationDetailsDTOList),
		TxId:                 string(transaction.ID),
		OpState:              transaction.OpState,
		Scopes:               transaction.Scope,
	}, nil)
}

// PrepareCredential requests claim data and prepares VC for signing by issuer.
// POST /issuer/interactions/prepare-credential.
func (c *Controller) PrepareCredential(e echo.Context) error {
	var body PrepareCredential

	if err := util.ReadBody(e, &body); err != nil {
		return err
	}

	requestedFormat := lo.FromPtr(body.Format)
	_, err := common.ValidateVCFormat(common.VCFormat(requestedFormat))
	if err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "format", err)
	}

	ctx := e.Request().Context()

	result, err := c.oidc4ciService.PrepareCredential(
		ctx,
		&oidc4ci.PrepareCredential{
			TxID: issuecredential.TxID(body.TxId),
			CredentialRequests: []*oidc4ci.PrepareCredentialRequest{
				{
					CredentialTypes:  body.Types,
					CredentialFormat: vcsverifiable.OIDCFormat(requestedFormat),
					DID:              lo.FromPtr(body.Did),
					AudienceClaim:    body.AudienceClaim,
					HashedToken:      body.HashedToken,
				},
			},
		},
	)

	if err != nil {
		var custom *resterr.CustomError
		if errors.As(err, &custom) {
			return custom
		}

		return resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "PrepareCredential", err)
	}

	if len(result.Credentials) == 0 {
		return resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "PrepareCredential",
			errors.New("empty credentials list"))
	}

	profile, err := c.accessProfile(result.ProfileID, result.ProfileVersion)
	if err != nil {
		return err
	}

	prepareCredentialResult, err := c.prepareCredential(
		ctx,
		body.TxId,
		profile,
		result.Credentials,
		[]*RequestedCredentialResponseEncryption{body.RequestedCredentialResponseEncryption},
	)
	if err != nil {
		return err
	}

	return util.WriteOutput(e)(prepareCredentialResult[0], nil)
}

func (c *Controller) prepareCredential(
	ctx context.Context,
	txID string,
	profile *profileapi.Issuer,
	credentials []*oidc4ci.PrepareCredentialResultData,
	requestedCredentialResponseEncryption []*RequestedCredentialResponseEncryption,
) ([]PrepareCredentialResult, error) {
	var result []PrepareCredentialResult
	var resultErr error
	var mut sync.Mutex
	var wg sync.WaitGroup

	for index1, credentialData1 := range credentials {
		if credentialData1.Credential == nil {
			return nil, resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "PrepareCredential",
				errors.New("credentials should not be nil"))
		}

		credentialData := credentialData1
		index := index1

		wg.Add(1)
		go func() {
			defer wg.Done()

			singleResp, singleErr := c.issueSingleCredential(
				ctx,
				credentialData,
				txID,
				profile,
				requestedCredentialResponseEncryption,
				index,
			)

			mut.Lock()
			defer mut.Unlock()

			if singleResp != nil {
				result = append(result, *singleResp)
			}

			if singleErr != nil {
				resultErr = errors.Join(resultErr, singleErr)
			}
		}()
	}

	wg.Wait()

	if resultErr != nil {
		return nil, resultErr
	}

	return result, nil
}

func (c *Controller) issueSingleCredential(
	ctx context.Context,
	credentialData *oidc4ci.PrepareCredentialResultData,
	txID string,
	profile *profileapi.Issuer,
	requestedCredentialResponseEncryption []*RequestedCredentialResponseEncryption,
	index int,
) (*PrepareCredentialResult, error) {
	if err := c.validateClaims(
		ctx,
		profile.VCConfig,
		credentialData.Credential,
		credentialData.CredentialTemplate,
		credentialData.EnforceStrictValidation,
	); err != nil {
		return nil, resterr.NewCustomError(resterr.ClaimsValidationErr, err)
	}

	if err := validateCredentialResponseEncryption(profile, requestedCredentialResponseEncryption[index]); err != nil {
		return nil, resterr.NewValidationError(resterr.OIDCInvalidEncryptionParameters,
			"credential_response_encryption", err)
	}

	signedCredential, err := c.signCredential(
		ctx,
		credentialData.Credential,
		profile,
		issuecredential.WithTransactionID(txID),
		issuecredential.WithSkipIDPrefix(),
	)
	if err != nil {
		return nil, err
	}

	return &PrepareCredentialResult{
		Credential:     signedCredential,
		Format:         string(credentialData.Format),
		OidcFormat:     string(credentialData.OidcFormat),
		Retry:          credentialData.Retry,
		NotificationId: credentialData.NotificationID,
	}, nil
}

// PrepareBatchCredential requests claim data and prepares batch of requested VC for signing by issuer.
// POST /issuer/interactions/prepare-credential-batch.
func (c *Controller) PrepareBatchCredential(e echo.Context) error {
	var body PrepareBatchCredential

	if err := util.ReadBody(e, &body); err != nil {
		return err
	}

	ctx := e.Request().Context()

	var (
		credentialRequests                    []*oidc4ci.PrepareCredentialRequest
		requestedCredentialResponseEncryption []*RequestedCredentialResponseEncryption
	)
	for _, credentialRequested := range body.CredentialRequests {
		requestedFormat := lo.FromPtr(credentialRequested.Format)
		_, err := common.ValidateVCFormat(common.VCFormat(requestedFormat))
		if err != nil {
			return resterr.NewValidationError(resterr.InvalidValue, "format", err)
		}

		credentialRequests = append(credentialRequests, &oidc4ci.PrepareCredentialRequest{
			CredentialTypes:  credentialRequested.Types,
			CredentialFormat: vcsverifiable.OIDCFormat(requestedFormat),
			DID:              lo.FromPtr(credentialRequested.Did),
			AudienceClaim:    credentialRequested.AudienceClaim,
			HashedToken:      credentialRequested.HashedToken,
		})

		requestedCredentialResponseEncryption = append(
			requestedCredentialResponseEncryption, credentialRequested.RequestedCredentialResponseEncryption)
	}

	result, err := c.oidc4ciService.PrepareCredential(
		ctx,
		&oidc4ci.PrepareCredential{
			TxID:               issuecredential.TxID(body.TxId),
			CredentialRequests: credentialRequests,
		},
	)

	if err != nil {
		var custom *resterr.CustomError
		if errors.As(err, &custom) {
			return custom
		}

		return resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "PrepareBatchCredential", err)
	}

	if len(result.Credentials) == 0 {
		return resterr.NewSystemError(resterr.IssuerOIDC4ciSvcComponent, "PrepareBatchCredential",
			errors.New("empty credentials list"))
	}

	profile, err := c.accessProfile(result.ProfileID, result.ProfileVersion)
	if err != nil {
		return err
	}

	prepareCredentialResult, err := c.prepareCredential(
		ctx,
		body.TxId,
		profile,
		result.Credentials,
		requestedCredentialResponseEncryption,
	)
	if err != nil {
		return err
	}

	return util.WriteOutput(e)(prepareCredentialResult, nil)
}

// CredentialIssuanceHistory returns Credential Issuance history.
// GET /issuer/profiles/{profileID}/issued-credentials.
func (c *Controller) CredentialIssuanceHistory(
	e echo.Context,
	profileID string,
	extraParams CredentialIssuanceHistoryParams,
) error {
	credentialMetadata, err := c.credentialIssuanceHistoryStore.
		GetIssuedCredentialsMetadata(
			e.Request().Context(),
			profileID,
			extraParams.TxID,
			extraParams.CredentialID,
		)
	if err != nil {
		return err
	}

	historyData := make([]CredentialIssuanceHistoryData, 0, len(credentialMetadata))
	for _, meta := range credentialMetadata {
		historyData = append(historyData, CredentialIssuanceHistoryData{
			CredentialId:    meta.CredentialID,
			CredentialTypes: meta.CredentialType,
			Issuer:          meta.Issuer,
			ProfileVersion:  lo.ToPtr(meta.ProfileVersion),
			ExpirationDate:  c.parseTime(meta.ExpirationDate),
			IssuanceDate:    c.parseTime(meta.IssuanceDate),
			TransactionId:   lo.ToPtr(meta.TransactionID),
		})
	}

	return util.WriteOutput(e)(historyData, nil)
}

func (c *Controller) parseTime(t *utiltime.TimeWrapper) *string {
	if t == nil {
		return nil
	}

	return lo.ToPtr(t.Time.Format(time.RFC3339))
}

func (c *Controller) validateClaims( //nolint:gocognit
	ctx context.Context,
	vcConfig *profileapi.VCConfig,
	cred *verifiable.Credential,
	credentialTemplate *profileapi.CredentialTemplate,
	validateJSONLD bool,
) error {
	if err := validateBaseContext(cred.Contents().Context, vcConfig); err != nil {
		return err
	}

	subjects, err := getCredentialSubjects(cred.Contents().Subject)
	if err != nil {
		return fmt.Errorf("get credential subjects: %w", err)
	}

	for _, sub := range subjects {
		if validateJSONLD {
			if err := c.validateJSONLD(cred, sub); err != nil {
				logger.Infoc(ctx, "Credential failed validation against JSONLD schema", log.WithError(err),
					logfields.WithCredentialID(cred.Contents().ID), logfields.WithContext(cred.Contents().Context))

				return err
			}
		}

		if credentialTemplate != nil && credentialTemplate.JSONSchemaID != "" {
			if err := c.validateJSONSchema(cred, credentialTemplate, sub); err != nil {
				logger.Infoc(ctx, "Credential failed validation against JSON schema", log.WithError(err),
					logfields.WithCredentialID(cred.Contents().ID),
					logfields.WithJSONSchemaID(credentialTemplate.JSONSchemaID))

				return err
			}
		}
	}

	return nil
}

func (c *Controller) validateJSONLD(
	cred *verifiable.Credential,
	sub verifiable.Subject,
) error {
	var ctx []interface{}
	for _, ct := range cred.Contents().Context {
		ctx = append(ctx, ct)
	}

	var types []interface{}
	for _, t := range cred.Contents().Types {
		types = append(types, t)
	}

	data := map[string]interface{}{}

	for k, v := range sub.CustomFields {
		if k == "type" || k == "@type" {
			if v1, ok1 := v.(string); ok1 {
				types = append(types, v1)

				continue
			}

			if reflect.TypeOf(v).Kind() == reflect.Slice {
				s := reflect.ValueOf(v)
				for i := 0; i < s.Len(); i++ {
					types = append(types, s.Index(i).Interface())
				}
			}

			continue
		}

		data[k] = v
	}

	data["@context"] = ctx
	data["type"] = types

	return validator.ValidateJSONLDMap(data,
		validator.WithDocumentLoader(c.documentLoader),
		validator.WithStrictValidation(true),
		validator.WithJSONLDIncludeDetailedStructureDiffOnError(),
	)
}

func (c *Controller) validateJSONSchema(
	cred *verifiable.Credential,
	credentialTemplate *profileapi.CredentialTemplate,
	sub verifiable.Subject,
) error {
	logger.Debug("Validating credential against JSON schema",
		logfields.WithCredentialID(cred.Contents().ID),
		logfields.WithCredentialTemplateID(credentialTemplate.ID),
		logfields.WithJSONSchemaID(credentialTemplate.JSONSchemaID),
	)

	return c.schemaValidator.Validate(sub.CustomFields, credentialTemplate.JSONSchemaID,
		[]byte(credentialTemplate.JSONSchema))
}

func getCredentialSubjects(subject interface{}) ([]verifiable.Subject, error) {
	if subject == nil {
		return nil, nil
	}

	if sub, ok := subject.(verifiable.Subject); ok {
		return []verifiable.Subject{sub}, nil
	}

	if subs, ok := subject.([]verifiable.Subject); ok {
		return subs, nil
	}

	return nil, fmt.Errorf("invalid type for credential subject: %T", subject)
}

func validateCredentialResponseEncryption(
	profile *profileapi.Issuer,
	requested *RequestedCredentialResponseEncryption,
) error {
	if profile.OIDCConfig == nil {
		return nil
	}

	if !profile.OIDCConfig.CredentialResponseEncryptionRequired && requested == nil {
		return nil
	}

	if profile.OIDCConfig.CredentialResponseEncryptionRequired && requested == nil {
		return resterr.NewValidationError(resterr.InvalidValue, "credential_response_encryption",
			errors.New("credential response encryption is required"))
	}

	alg := ""
	if requested != nil {
		alg = requested.Alg
	}

	if len(profile.OIDCConfig.CredentialResponseAlgValuesSupported) > 0 &&
		!lo.Contains(profile.OIDCConfig.CredentialResponseAlgValuesSupported, alg) {
		return resterr.NewValidationError(resterr.InvalidValue, "credential_response_encryption.alg",
			fmt.Errorf("alg %s not supported", alg))
	}

	enc := ""
	if requested != nil {
		enc = requested.Enc
	}

	if len(profile.OIDCConfig.CredentialResponseEncValuesSupported) > 0 &&
		!lo.Contains(profile.OIDCConfig.CredentialResponseEncValuesSupported, enc) {
		return resterr.NewValidationError(resterr.InvalidValue, "credential_response_encryption.enc",
			fmt.Errorf("enc %s not supported", enc))
	}

	return nil
}

// OpenidCredentialIssuerConfig request VCS IDP OIDC Configuration.
// GET /issuer/{profileID}/{profileVersion}/.well-known/openid-credential-issuer.
func (c *Controller) OpenidCredentialIssuerConfig(ctx echo.Context, profileID, profileVersion string) error {
	issuerProfile, err := c.profileSvc.GetProfile(profileID, profileVersion)
	if err != nil {
		return err
	}

	config, jwtSignedConfig, err := c.openidIssuerConfigProvider.GetOpenIDCredentialIssuerConfig(issuerProfile)
	if err != nil {
		return err
	}

	if jwtSignedConfig != "" {
		return util.WriteOutput(ctx)(WellKnownOpenIDIssuerConfiguration{
			SignedMetadata: &jwtSignedConfig,
		}, nil)
	}

	return util.WriteOutput(ctx)(config, nil)
}

// OpenidCredentialIssuerConfigV2 request VCS IDP OIDC Configuration.
// GET /oidc/idp/{profileID}/{profileVersion}/.well-known/openid-credential-issuer.
func (c *Controller) OpenidCredentialIssuerConfigV2(ctx echo.Context, profileID, profileVersion string) error {
	return c.OpenidCredentialIssuerConfig(ctx, profileID, profileVersion)
}

func (c *Controller) sendFailedEvent(ctx context.Context, orgID, profileID, profileVersion string, e error) {
	ep := oidc4ci.EventPayload{
		OrgID:          orgID,
		ProfileID:      profileID,
		ProfileVersion: profileVersion,
	}

	ep.Error, ep.ErrorCode, ep.ErrorComponent = resterr.GetErrorDetails(e)

	payload, err := c.marshal(ep)
	if err != nil {
		logger.Errorc(ctx, "Error sending event due to marshalling error", log.WithError(err))

		return
	}

	evt := spi.NewEventWithPayload(uuid.NewString(), "source://vcs/issuer", spi.IssuerOIDCInteractionFailed, payload)

	err = c.eventSvc.Publish(ctx, c.eventTopic, evt)
	if err != nil {
		logger.Errorc(ctx, "Error publishing failure event", log.WithError(err))

		return
	}
}

func getBaseContext(config *profileapi.VCConfig) (string, error) {
	switch config.Model {
	case vcsverifiable.V2_0:
		return verifiable.V2ContextURI, nil
	case vcsverifiable.V1_1, "":
		return verifiable.V1ContextURI, nil
	default:
		return "", fmt.Errorf("unsupported VC model: %s", config.Model)
	}
}

func validateBaseContext(contexts []string, config *profileapi.VCConfig) error {
	switch config.Model {
	case vcsverifiable.V2_0:
		if !verifiable.IsBaseContext(contexts, verifiable.V2ContextURI) {
			return fmt.Errorf("invalid context for model %s", config.Model)
		}

		return nil
	case vcsverifiable.V1_1, "":
		if !verifiable.IsBaseContext(contexts, verifiable.V1ContextURI) {
			return fmt.Errorf("invalid context for model %s", config.Model)
		}

		return nil
	default:
		return fmt.Errorf("unsupported VC model: %s", config.Model)
	}
}

func getJSONSchema(config *profileapi.VCConfig) (string, error) {
	switch config.Model {
	case vcsverifiable.V2_0:
		return verifiable.JSONSchemaLoaderV2(), nil
	case vcsverifiable.V1_1, "":
		return verifiable.JSONSchemaLoaderV1(verifiable.WithDisableRequiredField("issuanceDate")), nil
	default:
		return "", fmt.Errorf("unsupported VC model: %s", config.Model)
	}
}
