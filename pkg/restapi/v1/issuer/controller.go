/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package issuer -source=controller.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry

package issuer

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/labstack/echo/v4"

	"github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/issuer"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/util"
)

const (
	issuerProfileSvcComponent  = "issuer.ProfileService"
	issuerProfileCtrlComponent = "issuer.Controller"
	issuerKMSRegistryComponent = "kms.Registry"
	vcConfigKeyType            = "vcConfig.keyType"
	vcConfigFormat             = "vcConfig.format"
	vcConfigSigningAlgorithm   = "vcConfig.signingAlgorithm"
	vcConfigDidMethod          = "vcConfig.didMethod"
	kmsConfigType              = "kmsConfig.type"
	kmsConfigSecretLockKeyPath = "kmsConfig.secretLockKeyPath" //nolint: gosec
	kmsConfigEndpoint          = "kmsConfig.endpoint"
	kmsConfigDBURL             = "kmsConfig.dbURL"
	kmsConfigDBType            = "kmsConfig.dbType"
	kmsConfigDBPrefix          = "kmsConfig.dbPrefix"
	profileCredentialManifests = "credentialManifests" //nolint: gosec
	profileOrganizationID      = "organizationID"
	profileName                = "name"
)

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type kmsManager = kms.VCSKeyManager

type kmsRegistry interface {
	GetKeyManager(config *kms.Config) (kmsManager, error)
}

type profileService interface {
	Create(profile *issuer.Profile,
		credentialManifests []*cm.CredentialManifest) (*issuer.Profile, *issuer.SigningDID, error)
	Update(profile *issuer.ProfileUpdate) error
	Delete(profileID issuer.ProfileID) error
	GetProfile(profileID issuer.ProfileID) (*issuer.Profile, *issuer.SigningDID, error)
	ActivateProfile(profileID issuer.ProfileID) error
	DeactivateProfile(profileID issuer.ProfileID) error
	GetAllProfiles(orgID string) ([]*issuer.Profile, error)
}

// Controller for Issuer Profile Management API.
type Controller struct {
	profileSvc  profileService
	kmsRegistry kmsRegistry
}

// NewController creates a new controller for Issuer Profile Management API.
func NewController(profileSvc profileService, kmsRegistry kmsRegistry) *Controller {
	return &Controller{profileSvc, kmsRegistry}
}

// PostIssuerProfiles creates a new issuer profile.
// POST /issuer/profiles.
func (c *Controller) PostIssuerProfiles(ctx echo.Context) error {
	var body CreateIssuerProfileData

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.createProfile(ctx, &body))
}

func (c *Controller) createProfile(ctx echo.Context, body *CreateIssuerProfileData) (*IssuerProfile, error) {
	orgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return nil, err
	}

	profile, err := c.validateCreateProfileData(body, orgID)
	if err != nil {
		return nil, err
	}

	credentialManifests, err := c.validateCredentialManifests(body.CredentialManifests)
	if err != nil {
		return nil, err
	}

	createdProfile, signingDID, err := c.profileSvc.Create(profile, credentialManifests)
	if errors.Is(err, issuer.ErrProfileNameDuplication) {
		return nil, resterr.NewValidationError(resterr.AlreadyExist, profileName, err)
	}

	if err != nil {
		return nil, resterr.NewSystemError(issuerProfileSvcComponent, "CreateProfile", err)
	}

	return c.mapToIssuerProfile(createdProfile, signingDID)
}

// DeleteIssuerProfilesProfileID deletes profile.
// DELETE /issuer/profiles/{profileID}.
func (c *Controller) DeleteIssuerProfilesProfileID(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, _, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	err = c.profileSvc.Delete(profile.ID)
	if err != nil {
		return resterr.NewSystemError(issuerProfileSvcComponent, "DeleteProfile", err)
	}

	return nil
}

// GetIssuerProfilesProfileID gets a profile by ID.
// GET /issuer/profiles/{profileID}.
func (c *Controller) GetIssuerProfilesProfileID(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, signingDID, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.mapToIssuerProfile(profile, signingDID))
}

// PutIssuerProfilesProfileID updates a profile.
// PUT /issuer/profiles/{profileID}.
func (c *Controller) PutIssuerProfilesProfileID(ctx echo.Context, profileID string) error {
	var body UpdateIssuerProfileData

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, _, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	err = c.profileSvc.Update(&issuer.ProfileUpdate{
		ID:         profile.ID,
		Name:       strPtrToStr(body.Name),
		URL:        strPtrToStr(body.Url),
		OIDCConfig: body.OidcConfig,
	})
	if err != nil {
		return resterr.NewSystemError(issuerProfileSvcComponent, "UpdateProfile", err)
	}

	updated, signingDID, err := c.profileSvc.GetProfile(profile.ID)
	if err != nil {
		return resterr.NewSystemError(issuerProfileSvcComponent, "GetProfile", err)
	}

	return util.WriteOutput(ctx)(c.mapToIssuerProfile(updated, signingDID))
}

// PostIssuerProfilesProfileIDActivate activates a profile.
// POST /issuer/profiles/{profileID}/activate.
func (c *Controller) PostIssuerProfilesProfileIDActivate(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, _, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	err = c.profileSvc.ActivateProfile(profile.ID)
	if err != nil {
		return resterr.NewSystemError(issuerProfileSvcComponent, "ActivateProfile", err)
	}

	return nil
}

// PostIssuerProfilesProfileIDDeactivate deactivates a profile.
// POST /issuer/profiles/{profileID}/deactivate.
func (c *Controller) PostIssuerProfilesProfileIDDeactivate(ctx echo.Context, profileID string) error {
	oidcOrgID, err := util.GetOrgIDFromOIDC(ctx)
	if err != nil {
		return err
	}

	profile, _, err := c.accessProfile(profileID, oidcOrgID)
	if err != nil {
		return err
	}

	err = c.profileSvc.DeactivateProfile(profile.ID)
	if err != nil {
		return resterr.NewSystemError(issuerProfileSvcComponent, "DeactivateProfile", err)
	}

	return nil
}

func (c *Controller) validateCreateProfileData(body *CreateIssuerProfileData, orgID string) (*issuer.Profile, error) {
	if body.OrganizationID != orgID {
		return nil, resterr.NewValidationError(resterr.InvalidValue, profileOrganizationID,
			fmt.Errorf("org id(%s) from oidc not much profile org id(%s)", orgID, body.OrganizationID))
	}

	kmsConfig, err := c.validateKMSConfig(body.KmsConfig)
	if err != nil {
		return nil, err
	}

	keyManager, err := c.kmsRegistry.GetKeyManager(kmsConfig)
	if err != nil {
		return nil, resterr.NewSystemError(issuerKMSRegistryComponent, "GetKeyManager", err)
	}

	vcConfig, err := c.validateVCConfig(&body.VcConfig, keyManager.SupportedKeyTypes())
	if err != nil {
		return nil, err
	}

	return &issuer.Profile{
		URL:            body.Url,
		Name:           body.Name,
		Active:         true,
		OIDCConfig:     body.OidcConfig,
		OrganizationID: body.OrganizationID,
		VCConfig:       vcConfig,
		KMSConfig:      kmsConfig,
	}, nil
}

func (c *Controller) validateCredentialManifests(credentialManifests *[]map[string]interface{}) (
	[]*cm.CredentialManifest, error) {
	if credentialManifests == nil {
		return nil, nil
	}

	var result []*cm.CredentialManifest

	for _, manifest := range *credentialManifests {
		bytes, err := json.Marshal(manifest)
		if err != nil {
			return nil, resterr.NewSystemError(issuerProfileCtrlComponent, "jsonMarshal",
				fmt.Errorf("validate credentials: marshal json %w", err))
		}

		decoded := &cm.CredentialManifest{}
		err = json.Unmarshal(bytes, decoded)

		if err != nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, profileCredentialManifests,
				fmt.Errorf("validate credentials: marshal json %w", err))
		}

		result = append(result, decoded)
	}

	return result, nil
}

func (c *Controller) validateKMSConfig(config *KMSConfig) (*kms.Config, error) {
	if config == nil {
		return nil, nil //nolint: nilnil
	}

	kmsType, err := c.validateKMSType(config.Type)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigType, err)
	}

	if kmsType == kms.AWS || kmsType == kms.Web {
		if config.Endpoint == nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigEndpoint,
				fmt.Errorf("enpoint is required for %s kms", config.Type))
		}
		return &kms.Config{
			KMSType:  kmsType,
			Endpoint: *config.Endpoint,
		}, nil
	}

	if config.SecretLockKeyPath == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigSecretLockKeyPath,
			fmt.Errorf("secretLockKeyPath is required for %s kms", config.Type))
	}

	if config.DbType == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigDBType,
			fmt.Errorf("dbType is required for %s kms", config.Type))
	}

	if config.DbURL == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigDBURL,
			fmt.Errorf("dbURL is required for %s kms", config.Type))
	}

	if config.DbPrefix == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigDBPrefix,
			fmt.Errorf("dbPrefix is required for %s kms", config.Type))
	}

	return &kms.Config{
		KMSType:           kmsType,
		SecretLockKeyPath: *config.SecretLockKeyPath,
		DBType:            *config.DbType,
		DBURL:             *config.DbURL,
		DBPrefix:          *config.DbPrefix,
	}, nil
}

func (c *Controller) validateVCConfig(vcConfig *VCConfig,
	supportedKeyTypes []arieskms.KeyType) (*issuer.VCConfig, error) {
	vcFormat, err := c.validateVCFormat(vcConfig.Format)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, vcConfigFormat, err)
	}

	signingAlgorithm, err := vc.ValidateVCSignatureAlgorithm(vcFormat, vcConfig.SigningAlgorithm, supportedKeyTypes)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, vcConfigSigningAlgorithm,
			fmt.Errorf("issuer profile service: create profile failed %w", err))
	}

	keyType, err := vc.ValidateSignatureKeyType(signingAlgorithm, strPtrToStr(vcConfig.KeyType))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, vcConfigKeyType,
			fmt.Errorf("issuer profile service: create profile failed %w", err))
	}

	didMethod, err := c.validateDIDMethod(vcConfig.DidMethod)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, vcConfigDidMethod, err)
	}

	var contexts []string
	if vcConfig.Contexts != nil {
		contexts = *vcConfig.Contexts
	}

	return &issuer.VCConfig{
		Format:           vcFormat,
		SigningAlgorithm: signingAlgorithm,
		KeyType:          keyType,
		DIDMethod:        didMethod,
		Status:           vcConfig.Status,
		Context:          contexts,
	}, nil
}

func (c *Controller) accessProfile(profileID string, oidcOrgID string) (*issuer.Profile, *issuer.SigningDID, error) {
	profile, signingDID, err := c.profileSvc.GetProfile(profileID)
	if errors.Is(err, issuer.ErrDataNotFound) {
		return nil, nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
			fmt.Errorf("profile with given id %s, dosn't exists", profileID))
	}

	if err != nil {
		return nil, nil, resterr.NewSystemError(issuerProfileSvcComponent, "GetProfile", err)
	}

	// Profiles of other organization is not visible.
	if profile.OrganizationID != oidcOrgID {
		return nil, nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
			fmt.Errorf("profile with given id %s, dosn't exists", profileID))
	}

	return profile, signingDID, nil
}

func (c *Controller) validateKMSType(kmsType KMSConfigType) (kms.Type, error) {
	switch kmsType {
	case KMSConfigTypeAws:
		return kms.AWS, nil
	case KMSConfigTypeLocal:
		return kms.Local, nil
	case KMSConfigTypeWeb:
		return kms.Web, nil
	}

	return "", fmt.Errorf("unsupported kms type %s, use one of next [%s, %s, %s]",
		kmsType, KMSConfigTypeAws, KMSConfigTypeLocal, KMSConfigTypeWeb)
}

func (c *Controller) mapToKMSConfigType(kmsType kms.Type) (KMSConfigType, error) {
	switch kmsType {
	case kms.AWS:
		return KMSConfigTypeAws, nil
	case kms.Local:
		return KMSConfigTypeLocal, nil
	case kms.Web:
		return KMSConfigTypeWeb, nil
	}

	return "", resterr.NewSystemError(issuerProfileCtrlComponent, "mapToKMSConfigType",
		fmt.Errorf("kms type missmatch %s, rest api supportes only [%s, %s, %s]",
			kmsType, KMSConfigTypeAws, KMSConfigTypeLocal, KMSConfigTypeWeb))
}

func (c *Controller) validateVCFormat(format VCConfigFormat) (vc.Format, error) {
	switch format {
	case JwtVc:
		return vc.JwtVC, nil
	case LdpVc:
		return vc.LdpVC, nil
	}

	return "", fmt.Errorf("unsupported vc format %s, use one of next [%s, %s]", format, JwtVc, LdpVc)
}

func (c *Controller) mapToVCFormat(format vc.Format) (VCConfigFormat, error) {
	switch format {
	case vc.JwtVC:
		return JwtVc, nil
	case vc.LdpVC:
		return LdpVc, nil
	}

	return "", resterr.NewSystemError(issuerProfileCtrlComponent, "mapToVCFormat",
		fmt.Errorf("vc format missmatch %s, rest api supports only [%s, %s]", format, JwtVc, LdpVc))
}

func (c *Controller) validateDIDMethod(method VCConfigDidMethod) (did.Method, error) {
	switch method {
	case VCConfigDidMethodKey:
		return did.KeyDIDMethod, nil
	case VCConfigDidMethodWeb:
		return did.WebDIDMethod, nil
	case VCConfigDidMethodOrb:
		return did.OrbDIDMethod, nil
	}

	return "", fmt.Errorf("unsupported did method %s, use one of next [%s, %s, %s]",
		method, VCConfigDidMethodKey, VCConfigDidMethodWeb, VCConfigDidMethodOrb)
}

func (c *Controller) mapToDIDMethod(method did.Method) (VCConfigDidMethod, error) {
	switch method {
	case did.KeyDIDMethod:
		return VCConfigDidMethodKey, nil
	case did.WebDIDMethod:
		return VCConfigDidMethodWeb, nil
	case did.OrbDIDMethod:
		return VCConfigDidMethodOrb, nil
	}

	return "", resterr.NewSystemError(issuerProfileCtrlComponent, "mapToDIDMethod",
		fmt.Errorf("did method missmatch %s, rest api supports only [%s, %s, %s]",
			method, VCConfigDidMethodKey, VCConfigDidMethodWeb, VCConfigDidMethodOrb))
}

func (c *Controller) mapToIssuerProfile(p *issuer.Profile, signingDID *issuer.SigningDID) (*IssuerProfile, error) {
	format, err := c.mapToVCFormat(p.VCConfig.Format)
	if err != nil {
		return nil, err
	}

	didMethod, err := c.mapToDIDMethod(p.VCConfig.DIDMethod)
	if err != nil {
		return nil, err
	}

	keyType := string(p.VCConfig.KeyType)
	signingAlgorithm := string(p.VCConfig.SigningAlgorithm)

	var kmsConfig *KMSConfig

	if p.KMSConfig != nil {
		kmsType, err := c.mapToKMSConfigType(p.KMSConfig.KMSType)
		if err != nil {
			return nil, err
		}

		kmsConfig = &KMSConfig{
			DbPrefix:          &p.KMSConfig.DBPrefix,
			DbType:            &p.KMSConfig.DBType,
			DbURL:             &p.KMSConfig.DBURL,
			Endpoint:          &p.KMSConfig.Endpoint,
			SecretLockKeyPath: &p.KMSConfig.SecretLockKeyPath,
			Type:              kmsType,
		}
	}

	vcConfig := VCConfig{
		Contexts:         &p.VCConfig.Context,
		DidMethod:        didMethod,
		Format:           format,
		KeyType:          &keyType,
		SigningAlgorithm: signingAlgorithm,
		SigningDID:       signingDID.DID,
	}

	profile := &IssuerProfile{
		Active:         p.Active,
		Id:             p.ID,
		KmsConfig:      kmsConfig,
		Name:           p.Name,
		OrganizationID: p.OrganizationID,
		Url:            p.URL,
		VcConfig:       vcConfig,
	}

	var (
		m  map[string]interface{}
		ok bool
	)

	if p.VCConfig.Status != nil {
		m, ok = p.VCConfig.Status.(map[string]interface{})
		if !ok {
			return nil, resterr.NewSystemError(issuerProfileCtrlComponent, "TypeCast",
				fmt.Errorf("issuer profile vc config status has invalid type"))
		}

		profile.VcConfig.Status = &m
	}

	if p.OIDCConfig != nil {
		m, ok = p.OIDCConfig.(map[string]interface{})
		if !ok {
			return nil, resterr.NewSystemError(issuerProfileCtrlComponent, "TypeCast",
				fmt.Errorf("issuer profile oidc config has invalid type"))
		}

		profile.OidcConfig = &m
	}

	return profile, nil
}

func strPtrToStr(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}
