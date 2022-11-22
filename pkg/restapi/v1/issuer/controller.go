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
	"strings"
	"time"

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
	Publish(topic string, messages ...*spi.Event) error
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
	GetRevocationListVC(id string) (*verifiable.Credential, error)
	GetCredentialStatusURL(issuerProfileURL, issuerProfileID, statusID string) (string, error)
	UpdateVCStatus(signer *vc.Signer, profileName, CredentialID, status string) error
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

func (c *Controller) issueCredential(ctx echo.Context, body *IssueCredentialData,
	profileID string) (*verifiable.Credential, error) {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return nil, err
	}

	profile, err := c.accessOIDCProfile(profileID, oidcOrgID)
	if err != nil {
		return nil, err
	}

	return c.signCredential(body.Credential, body.Options, profile)
}

func (c *Controller) signCredential(
	cred interface{},
	opts *IssueCredentialOptions,
	profile *profileapi.Issuer,
) (*verifiable.Credential, error) {
	vcSchema := verifiable.JSONSchemaLoader(verifiable.WithDisableRequiredField("issuanceDate"))

	credential, err := vc.ValidateCredential(cred, []vcsverifiable.Format{profile.VCConfig.Format},
		verifiable.WithDisabledProofCheck(),
		verifiable.WithSchema(vcSchema),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	credOpts, err := validateIssueCredOptions(opts, profile)
	if err != nil {
		return nil, err
	}

	signedVC, err := c.issueCredentialService.IssueCredential(credential, credOpts, profile)
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

// GetCredentialsStatus retrieves the credential status.
// GET /issuer/profiles/{profileID}/credentials/status/{statusID}.
func (c *Controller) GetCredentialsStatus(ctx echo.Context, profileID string, statusID string) error {
	profile, err := c.accessProfile(profileID)
	if err != nil {
		return err
	}

	statusURL, err := c.vcStatusManager.GetCredentialStatusURL(profile.URL, profile.ID, statusID)
	if err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.vcStatusManager.GetRevocationListVC(statusURL))
}

// PostCredentialsStatus updates credential status.
// POST /issuer/profiles/{profileID}/credentials/status.
func (c *Controller) PostCredentialsStatus(ctx echo.Context, profileID string) error {
	var body UpdateCredentialStatusRequest

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	if err := c.updateCredentialStatus(ctx, &body, profileID); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusOK)
}

func (c *Controller) updateCredentialStatus(ctx echo.Context, body *UpdateCredentialStatusRequest,
	profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessOIDCProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	keyManager, err := c.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return fmt.Errorf("failed to get kms: %w", err)
	}

	if body.CredentialStatus.Type != string(profile.VCConfig.Status.Type) {
		return resterr.NewValidationError(resterr.InvalidValue, "CredentialStatus.Type",
			fmt.Errorf(
				"vc status list version %s not supported by current profile", body.CredentialStatus.Type))
	}

	signer := &vc.Signer{
		Format:                  profile.VCConfig.Format,
		DID:                     profile.SigningDID.DID,
		Creator:                 profile.SigningDID.Creator,
		SignatureType:           profile.VCConfig.SigningAlgorithm,
		KeyType:                 profile.VCConfig.KeyType,
		KMS:                     keyManager,
		SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
		VCStatusListType:        profile.VCConfig.Status.Type,
	}

	err = c.vcStatusManager.UpdateVCStatus(signer, profile.Name, body.CredentialID, body.CredentialStatus.Status)
	if err != nil {
		return resterr.NewSystemError("VCStatusManager", "UpdateVCStatus", err)
	}

	return nil
}

// InitiateCredentialIssuance initiates OIDC credential issuance flow.
// POST /issuer/profiles/{profileID}/interactions/initiate-oidc.
func (c *Controller) InitiateCredentialIssuance(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessOIDCProfile(profileID, oidcOrgID)
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
		InitiateIssuanceUrl: resp.InitiateIssuanceURL,
		TxId:                string(resp.TxID),
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

	return &PrepareClaimDataAuthorizationResponse{
		AuthorizationRequest: OAuthParameters{
			ClientId:     resp.AuthorizationParameters.ClientID,
			ClientSecret: resp.AuthorizationParameters.ClientSecret,
			ResponseType: resp.AuthorizationParameters.ResponseType,
			Scope:        resp.AuthorizationParameters.Scope,
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
				fmt.Errorf("profile with given id %s, dosn't exists", profileID))
		}

		return nil, resterr.NewSystemError(issuerProfileSvcComponent, "GetProfile", err)
	}

	return profile, nil
}

func (c *Controller) accessOIDCProfile(profileID string, oidcOrgID string) (*profileapi.Issuer, error) {
	profile, err := c.accessProfile(profileID)
	if err != nil {
		return nil, err
	}

	// Profiles of other organization is not visible.
	if profile.OrganizationID != oidcOrgID {
		return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
			fmt.Errorf("profile with given id %s, dosn't exists", profileID))
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

	result, err := c.oidc4ciService.PrepareCredential(ctx.Request().Context(),
		&oidc4ci.PrepareCredential{
			TxID:             oidc4ci.TxID(body.TxId),
			CredentialType:   body.Type,
			CredentialFormat: vcFormat,
			DID:              lo.FromPtr(body.Did),
		},
	)
	if err != nil {
		return resterr.NewSystemError("OIDC4CIService", "PrepareCredential", err)
	}

	profile, err := c.accessProfile(result.ProfileID)
	if err != nil {
		return err
	}

	signedCredential, err := c.signCredential(result.Credential, nil, profile)
	if err != nil {
		return err
	}

	return util.WriteOutput(ctx)(PrepareCredentialResult{
		Credential: signedCredential,
		Format:     string(result.Format),
		Retry:      result.Retry,
	}, nil)
}

// OpenidConfig request openid configuration for issuer.
// GET /issuer/{profileID}/.well-known/openid-configuration.
func (c *Controller) OpenidConfig(ctx echo.Context, profileID string) error {
	return util.WriteOutput(ctx)(c.getOpenIDConfig(profileID), nil)
}

func (c *Controller) getOpenIDConfig(profileID string) *WellKnownOpenIDConfiguration {
	host := c.externalHostURL
	if !strings.HasSuffix(host, "/") {
		host += "/"
	}

	return &WellKnownOpenIDConfiguration{
		AuthorizationEndpoint: fmt.Sprintf("%soidc/authorize", host),
		Issuer:                fmt.Sprintf("%s%s", host, profileID),
		ResponseTypesSupported: []string{
			"code",
		},
		TokenEndpoint:       fmt.Sprintf("%soidc/token", host),
		CredentialSupported: true,
		CredentialEndpoint:  fmt.Sprintf("%soidc/credential", host),
	}
}
