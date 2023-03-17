/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package verifier -source=controller.go -mock_names profileService=MockProfileService,verifyCredentialSvc=MockVerifyCredentialService,kmsRegistry=MockKMSRegistry,oidc4VPService=MockOIDC4VPService

package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vp"
	"github.com/trustbloc/vcs/pkg/kms"
	noopMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/noop"
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
	oidc4vpSvcComponent          = "oidc4vp.Service"

	vpSubmissionProperty = "presentation_submission"
)

var logger = log.New("oidc4vp")

type authorizationResponse struct {
	IDToken string
	VPToken []string
	State   string
}

type IDTokenVPToken struct {
	// TODO: use *presexch.PresentationSubmission instead of map[string]interface{}
	PresentationSubmission map[string]interface{} `json:"presentation_submission"`
}

type IDTokenClaims struct {
	VPToken IDTokenVPToken `json:"_vp_token"`
	Nonce   string         `json:"nonce"`
	Exp     int64          `json:"exp"`
}

type VPTokenClaims struct {
	VP    json.RawMessage `json:"vp"`
	Nonce string          `json:"nonce"`
	Exp   int64           `json:"exp"`
}

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
	VerifyCredential(ctx context.Context, credential *verifiable.Credential, opts *verifycredential.Options,
		profile *profileapi.Verifier) ([]verifycredential.CredentialsVerificationCheckResult, error)
}

type verifyPresentationSvc interface {
	VerifyPresentation(presentation *verifiable.Presentation, opts *verifypresentation.Options,
		profile *profileapi.Verifier) ([]verifypresentation.PresentationVerificationCheckResult, error)
}

type oidc4VPService interface {
	InitiateOidcInteraction(
		ctx context.Context,
		presentationDefinition *presexch.PresentationDefinition,
		purpose string,
		profile *profileapi.Verifier,
	) (*oidc4vp.InteractionInfo, error)

	VerifyOIDCVerifiablePresentation(txID oidc4vp.TxID, token []*oidc4vp.ProcessedVPToken) error

	GetTx(id oidc4vp.TxID) (*oidc4vp.Transaction, error)

	RetrieveClaims(tx *oidc4vp.Transaction) map[string]oidc4vp.CredentialMetadata
}

type Config struct {
	VerifyCredentialSvc   verifyCredentialSvc
	VerifyPresentationSvc verifyPresentationSvc
	ProfileSvc            profileService
	KMSRegistry           kmsRegistry
	DocumentLoader        ld.DocumentLoader
	VDR                   vdrapi.Registry
	OIDCVPService         oidc4VPService
	JWTVerifier           jose.SignatureVerifier
	Metrics               metricsProvider
}

type metricsProvider interface {
	CheckAuthorizationResponseTime(value time.Duration)
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
	jwtVerifier           jose.SignatureVerifier
	metrics               metricsProvider
}

// NewController creates a new controller for Verifier Profile Management API.
func NewController(config *Config) *Controller {
	if config.JWTVerifier == nil {
		config.JWTVerifier = jwt.NewVerifier(jwt.KeyResolverFunc(
			verifiable.NewVDRKeyResolver(config.VDR).PublicKeyFetcher()))
	}

	metrics := config.Metrics

	if metrics == nil {
		metrics = &noopMetricsProvider.NoMetrics{}
	}

	return &Controller{
		verifyCredentialSvc:   config.VerifyCredentialSvc,
		verifyPresentationSvc: config.VerifyPresentationSvc,
		profileSvc:            config.ProfileSvc,
		kmsRegistry:           config.KMSRegistry,
		documentLoader:        config.DocumentLoader,
		vdr:                   config.VDR,
		oidc4VPService:        config.OIDCVPService,
		jwtVerifier:           config.JWTVerifier,
		metrics:               metrics,
	}
}

// PostVerifyCredentials Verify credential
// (POST /verifier/profiles/{profileID}/credentials/verify).
func (c *Controller) PostVerifyCredentials(ctx echo.Context, profileID string) error {
	logger.Debug("PostVerifyCredentials begin")
	var body VerifyCredentialData

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.verifyCredential(ctx, &body, profileID))
}

func (c *Controller) verifyCredential(ctx echo.Context, body *VerifyCredentialData, //nolint:dupl
	profileID string) (*VerifyCredentialResponse, error) {
	tenantID, err := util.GetTenantIDFromRequest(ctx)
	if err != nil {
		return nil, err
	}

	profile, err := c.accessProfile(profileID, tenantID)
	if err != nil {
		return nil, err
	}

	credential, err := vc.ValidateCredential(
		body.Credential,
		profile.Checks.Credential.Format,
		profile.Checks.Credential.CredentialExpiry,
		profile.Checks.Credential.Strict,
		c.documentLoader,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(c.vdr).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader),
	)

	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	verRes, err := c.verifyCredentialSvc.VerifyCredential(
		ctx.Request().Context(), credential, getVerifyCredentialOptions(body.Options), profile)
	if err != nil {
		return nil, resterr.NewSystemError(verifyCredentialSvcComponent, "VerifyCredential", err)
	}

	logger.Debug("PostVerifyCredentials success")
	return mapVerifyCredentialChecks(verRes), nil
}

// PostVerifyPresentation Verify presentation.
// (POST /verifier/profiles/{profileID}/presentations/verify).
func (c *Controller) PostVerifyPresentation(ctx echo.Context, profileID string) error {
	logger.Debug("PostVerifyPresentation begin")
	var body VerifyPresentationData

	if err := util.ReadBody(ctx, &body); err != nil {
		return err
	}

	return util.WriteOutput(ctx)(c.verifyPresentation(ctx, &body, profileID))
}

func (c *Controller) verifyPresentation(ctx echo.Context, body *VerifyPresentationData, //nolint:dupl
	profileID string) (*VerifyPresentationResponse, error) {
	tenantID, err := util.GetTenantIDFromRequest(ctx)
	if err != nil {
		return nil, err
	}

	profile, err := c.accessProfile(profileID, tenantID)
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

	logger.Debug("PostVerifyPresentation success")
	return mapVerifyPresentationChecks(verRes), nil
}

func (c *Controller) InitiateOidcInteraction(ctx echo.Context, profileID string) error {
	logger.Debug("InitiateOidcInteraction begin")

	tenantID, err := util.GetTenantIDFromRequest(ctx)
	if err != nil {
		return err
	}

	profile, err := c.accessProfile(profileID, tenantID)
	if err != nil {
		return err
	}

	var body InitiateOIDC4VPData

	if err = ctx.Bind(&body); err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "requestBody", err)
	}

	return util.WriteOutput(ctx)(c.initiateOidcInteraction(ctx.Request().Context(), &body, profile))
}

func (c *Controller) initiateOidcInteraction(
	ctx context.Context,
	data *InitiateOIDC4VPData,
	profile *profileapi.Verifier,
) (*InitiateOIDC4VPResponse, error) {
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

	logger.Debug("InitiateOidcInteraction pd find", logfields.WithPresDefID(pd.ID))

	result, err := c.oidc4VPService.InitiateOidcInteraction(ctx, pd, strPtrToStr(data.Purpose), profile)
	if err != nil {
		return nil, resterr.NewSystemError("oidc4VPService", "InitiateOidcInteraction", err)
	}

	logger.Debug("InitiateOidcInteraction success", log.WithTxID(string(result.TxID)))
	return &InitiateOIDC4VPResponse{
		AuthorizationRequest: result.AuthorizationRequest,
		TxID:                 string(result.TxID),
	}, err
}

func (c *Controller) CheckAuthorizationResponse(ctx echo.Context) error {
	logger.Debug("CheckAuthorizationResponse begin")
	startTime := time.Now()

	defer func() {
		c.metrics.CheckAuthorizationResponseTime(time.Since(startTime))
		logger.Debug("CheckAuthorizationResponse end", log.WithDuration(time.Since(startTime)))
	}()

	authResp, err := validateAuthorizationResponse(ctx)
	if err != nil {
		return err
	}

	processedTokens, err := c.verifyAuthorizationResponseTokens(authResp)
	if err != nil {
		return err
	}

	err = c.oidc4VPService.VerifyOIDCVerifiablePresentation(oidc4vp.TxID(authResp.State), processedTokens)
	if err != nil {
		return err
	}

	logger.Debug("CheckAuthorizationResponse succeed")

	return nil
}

func (c *Controller) RetrieveInteractionsClaim(ctx echo.Context, txID string) error {
	logger.Debug("RetrieveInteractionsClaim begin")

	tenantID, err := util.GetTenantIDFromRequest(ctx)
	if err != nil {
		return err
	}

	tx, err := c.accessOIDC4VPTx(txID)
	if err != nil {
		return err
	}

	_, err = c.accessProfile(tx.ProfileID, tenantID)
	if err != nil {
		return err
	}

	if tx.ReceivedClaimsID == "" {
		return fmt.Errorf("claims were not received for transaction '%s'", txID)
	}

	if tx.ReceivedClaims == nil {
		return fmt.Errorf("claims expired for transaction '%s'", txID)
	}

	claims := c.oidc4VPService.RetrieveClaims(tx)

	logger.Debug("RetrieveInteractionsClaim succeed")

	return util.WriteOutput(ctx)(claims, nil)
}

func (c *Controller) accessOIDC4VPTx(txID string) (*oidc4vp.Transaction, error) {
	tx, err := c.oidc4VPService.GetTx(oidc4vp.TxID(txID))

	if err != nil {
		if errors.Is(err, oidc4vp.ErrDataNotFound) {
			return nil, resterr.NewValidationError(resterr.DoesntExist, "txID",
				fmt.Errorf("transaction with given id %s, doesn't exist", txID))
		}

		return nil, resterr.NewSystemError(oidc4vpSvcComponent, "GetTx", err)
	}

	logger.Debug("RetrieveInteractionsClaim tx found", log.WithTxID(string(tx.ID)))

	return tx, nil
}

func (c *Controller) verifyAuthorizationResponseTokens(authResp *authorizationResponse) (
	[]*oidc4vp.ProcessedVPToken, error) {
	startTime := time.Now()
	defer func() {
		logger.Debug("validateResponseAuthTokens", log.WithDuration(time.Since(startTime)))
	}()

	idTokenClaims, err := validateIDToken(authResp.IDToken, c.jwtVerifier)
	if err != nil {
		return nil, err
	}

	logger.Debug("CheckAuthorizationResponse id_token verified")

	var processedVPTokens []*oidc4vp.ProcessedVPToken

	for _, vpt := range authResp.VPToken {
		vpTokenClaims, signer, err := validateVPToken(vpt, c.jwtVerifier)
		if err != nil {
			return nil, err
		}

		logger.Debug("CheckAuthorizationResponse vp_token verified")

		if vpTokenClaims.Nonce != idTokenClaims.Nonce {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "nonce",
				errors.New("nonce should be the same for both id_token and vp_token"))
		}

		presentation, err := verifiable.ParsePresentation(vpTokenClaims.VP,
			verifiable.WithPresPublicKeyFetcher(
				verifiable.NewVDRKeyResolver(c.vdr).PublicKeyFetcher(),
			),
			verifiable.WithPresJSONLDDocumentLoader(c.documentLoader),
		)
		if err != nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.vp", err)
		}

		logger.Debug("CheckAuthorizationResponse vp validated")

		presentation.JWT = vpt
		if presentation.CustomFields == nil {
			presentation.CustomFields = map[string]interface{}{}
		}

		presentation.Context = append(presentation.Context, presexch.PresentationSubmissionJSONLDContextIRI)
		presentation.Type = append(presentation.Type, presexch.PresentationSubmissionJSONLDType)
		presentation.CustomFields[vpSubmissionProperty] = idTokenClaims.VPToken.PresentationSubmission

		processedVPTokens = append(processedVPTokens, &oidc4vp.ProcessedVPToken{
			Nonce:        idTokenClaims.Nonce,
			Presentation: presentation,
			Signer:       signer,
		})
	}

	return processedVPTokens, nil
}

func validateIDToken(rawJwt string, verifier jose.SignatureVerifier) (*IDTokenClaims, error) {
	idTokenClaims := &IDTokenClaims{}

	_, err := verifyTokenSignature(rawJwt, idTokenClaims, verifier)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "id_token", err)
	}

	if idTokenClaims.Exp < time.Now().Unix() {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "id_token.exp", fmt.Errorf(
			"token expired"))
	}

	if idTokenClaims.VPToken.PresentationSubmission == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue,
			"id_token._vp_token.presentation_submission", fmt.Errorf(
				"$_vp_token.presentation_submission is missed"))
	}

	return idTokenClaims, nil
}
func validateVPToken(rawJwt string, verifier jose.SignatureVerifier) (*VPTokenClaims, string, error) {
	vpTokenClaims := &VPTokenClaims{}

	signer, err := verifyTokenSignature(rawJwt, vpTokenClaims, verifier)
	if err != nil {
		return nil, "", resterr.NewValidationError(resterr.InvalidValue, "vp_token", err)
	}

	if vpTokenClaims.Exp < time.Now().Unix() {
		return nil, "", resterr.NewValidationError(resterr.InvalidValue, "vp_token.exp", fmt.Errorf(
			"token expired"))
	}

	if vpTokenClaims.VP == nil {
		return nil, "", resterr.NewValidationError(resterr.InvalidValue, "vp_token.vp", fmt.Errorf(
			"$vp is missed"))
	}

	return vpTokenClaims, signer, nil
}

func verifyTokenSignature(rawJwt string, claims interface{}, verifier jose.SignatureVerifier) (string, error) {
	jsonWebToken, err := jwt.Parse(rawJwt, jwt.WithSignatureVerifier(verifier))
	if err != nil {
		return "", fmt.Errorf("parse JWT: %w", err)
	}

	err = jsonWebToken.DecodeClaims(claims)
	if err != nil {
		return "", fmt.Errorf("decode claims: %w", err)
	}

	kid, _ := jsonWebToken.Headers.KeyID()

	return strings.Split(kid, "#")[0], nil
}

func validateAuthorizationResponse(ctx echo.Context) (*authorizationResponse, error) {
	startTime := time.Now().UTC()
	defer func() {
		logger.Debug("validateAuthorizationResponse", log.WithDuration(time.Since(startTime)))
	}()
	req := ctx.Request()

	headerContentType := req.Header.Get("Content-Type")
	if headerContentType != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("content type is not application/x-www-form-urlencoded")
	}

	err := req.ParseForm()
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "body", err)
	}

	res := &authorizationResponse{}

	err = decodeFormValue(&res.IDToken, "id_token", req.PostForm)
	if err != nil {
		return nil, err
	}

	logger.Info("AuthorizationResponse id_token decoded", logfields.WithIDToken(res.IDToken))

	var vpTokenStr string

	err = decodeFormValue(&vpTokenStr, "vp_token", req.PostForm)
	if err != nil {
		return nil, err
	}

	res.VPToken = getVPTokens(vpTokenStr)

	logger.Debug("AuthorizationResponse vp_token decoded")

	err = decodeFormValue(&res.State, "state", req.PostForm)
	if err != nil {
		return nil, err
	}

	logger.Debug("AuthorizationResponse state decoded", log.WithState(res.State))

	return res, nil
}

func getVPTokens(tokenStr string) []string {
	var tokens []string

	if err := json.Unmarshal([]byte(tokenStr), &tokens); err != nil {
		return []string{tokenStr}
	}

	return tokens
}

func decodeFormValue(output *string, valName string, values url.Values) error {
	val := values[valName]
	if len(val) == 0 {
		return resterr.NewValidationError(resterr.InvalidValue, valName, fmt.Errorf("value is missed"))
	}

	if len(val) > 1 {
		return resterr.NewValidationError(resterr.InvalidValue, valName, fmt.Errorf("value is duplicated"))
	}

	*output = val[0]
	return nil
}

func (c *Controller) accessProfile(profileID string, tenantID string) (*profileapi.Verifier, error) {
	profile, err := c.profileSvc.GetProfile(profileID)
	if err != nil {
		if strings.Contains(err.Error(), "data not found") {
			return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
				fmt.Errorf("profile with given id %s, doesn't exist", profileID))
		}

		return nil, resterr.NewSystemError(verifierProfileSvcComponent, "GetProfile", err)
	}

	if profile == nil {
		return nil, resterr.NewValidationError(resterr.DoesntExist, "profile",
			fmt.Errorf("profile with given id %s, doesn't exist", profileID))
	}

	// Profiles of other organization is not visible.
	if profile.OrganizationID != tenantID {
		return nil, resterr.NewValidationError(resterr.DoesntExist, "organizationID",
			fmt.Errorf("profile with given org id %q, doesn't exist", tenantID))
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
