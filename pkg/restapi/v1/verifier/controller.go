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
	"regexp"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/valyala/fastjson"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/doc/vp"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
	"github.com/trustbloc/vcs/pkg/kms"
	noopMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/noop"
	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
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

var (
	logger         = log.New("oidc4vp")
	errMissedField = errors.New("missed field")
)

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
	Aud     string         `json:"aud"`
	Exp     int64          `json:"exp"`
}

type VPTokenClaims struct {
	Nonce         string
	Aud           string
	SignerDIDID   string
	VpTokenFormat vcsverifiable.Format
	VP            *verifiable.Presentation
}

type PresentationDefinition = json.RawMessage

var _ ServerInterface = (*Controller)(nil) // make sure Controller implements ServerInterface

type kmsManager = kms.VCSKeyManager

type kmsRegistry interface {
	GetKeyManager(config *kms.Config) (kmsManager, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Verifier, error)
}

type verifyCredentialSvc interface {
	verifycredential.ServiceInterface
}

type verifyPresentationSvc interface {
	verifypresentation.ServiceInterface
}

type oidc4VPService interface {
	oidc4vp.ServiceInterface
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
	Tracer                trace.Tracer
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
	tracer                trace.Tracer
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
		tracer:                config.Tracer,
	}
}

// PostVerifyCredentials Verify credential
// (POST /verifier/profiles/{profileID}/{profileVersion}/credentials/verify).
func (c *Controller) PostVerifyCredentials(e echo.Context, profileID, profileVersion string) error {
	logger.Debugc(e.Request().Context(), "PostVerifyCredentials begin")

	ctx, span := c.tracer.Start(e.Request().Context(), "PostVerifyCredentials")
	defer span.End()

	var body VerifyCredentialData

	if err := util.ReadBody(e, &body); err != nil {
		return err
	}

	span.SetAttributes(attributeutil.JSON("verify_credential_request", body, attributeutil.WithRedacted("credential")))

	tenantID, err := util.GetTenantIDFromRequest(e)
	if err != nil {
		return err
	}

	resp, err := c.verifyCredential(ctx, &body, profileID, profileVersion, tenantID)
	if err != nil {
		return err
	}

	return util.WriteOutput(e)(resp, nil)
}

func (c *Controller) verifyCredential(
	ctx context.Context,
	body *VerifyCredentialData,
	profileID string,
	profileVersion string,
	tenantID string,
) (*VerifyCredentialResponse, error) {
	profile, err := c.accessProfile(profileID, profileVersion, tenantID)
	if err != nil {
		return nil, err
	}

	credential, err := vc.ValidateCredential(
		ctx,
		body.Credential,
		profile.Checks.Credential.Format,
		profile.Checks.Credential.CredentialExpiry,
		profile.Checks.Credential.Strict,
		c.documentLoader,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader),
	)

	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	verRes, err := c.verifyCredentialSvc.VerifyCredential(ctx, credential,
		getVerifyCredentialOptions(body.Options), profile)
	if err != nil {
		return nil, resterr.NewSystemError(verifyCredentialSvcComponent, "VerifyCredential", err)
	}

	logger.Debugc(ctx, "PostVerifyCredentials success")
	return mapVerifyCredentialChecks(verRes), nil
}

// PostVerifyPresentation Verify presentation.
// (POST /verifier/profiles/{profileID}/{profileVersion}/presentations/verify).
func (c *Controller) PostVerifyPresentation(e echo.Context, profileID, profileVersion string) error {
	logger.Debugc(e.Request().Context(), "PostVerifyPresentation begin")

	ctx, span := c.tracer.Start(e.Request().Context(), "PostVerifyPresentation")
	defer span.End()

	var body VerifyPresentationData

	if err := util.ReadBody(e, &body); err != nil {
		return err
	}

	span.SetAttributes(attributeutil.JSON("verify_presentation_request", body,
		attributeutil.WithRedacted("presentation")))

	tenantID, err := util.GetTenantIDFromRequest(e)
	if err != nil {
		return err
	}

	resp, err := c.verifyPresentation(ctx, &body, profileID, profileVersion, tenantID)
	if err != nil {
		return err
	}

	return util.WriteOutput(e)(resp, nil)
}

func (c *Controller) verifyPresentation(ctx context.Context, body *VerifyPresentationData,
	profileID, profileVersion, tenantID string) (*VerifyPresentationResponse, error) {
	profile, err := c.accessProfile(profileID, profileVersion, tenantID)
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

	verRes, err := c.verifyPresentationSvc.VerifyPresentation(ctx, presentation,
		getVerifyPresentationOptions(body.Options), profile)
	if err != nil {
		return nil, resterr.NewSystemError(verifyCredentialSvcComponent, "VerifyCredential", err)
	}

	logger.Debugc(ctx, "PostVerifyPresentation success")
	return mapVerifyPresentationChecks(verRes), nil
}

// InitiateOidcInteraction initiates OpenID presentation flow through VCS.
// POST /verifier/profiles/{profileID}/{profileVersion}/interactions/initiate-oidc.
func (c *Controller) InitiateOidcInteraction(e echo.Context, profileID, profileVersion string) error {
	logger.Debugc(e.Request().Context(), "InitiateOidcInteraction begin")

	ctx, span := c.tracer.Start(e.Request().Context(), "InitiateOidcInteraction")
	defer span.End()

	tenantID, err := util.GetTenantIDFromRequest(e)
	if err != nil {
		return err
	}

	profile, err := c.accessProfile(profileID, profileVersion, tenantID)
	if err != nil {
		return err
	}

	var body InitiateOIDC4VPData

	if err = e.Bind(&body); err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "requestBody", err)
	}

	span.SetAttributes(attributeutil.JSON("initiate_oidc_request", body))

	resp, err := c.initiateOidcInteraction(ctx, &body, profile)
	if err != nil {
		return err
	}

	return util.WriteOutput(e)(resp, nil)
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

	logger.Debugc(ctx, "InitiateOidcInteraction pd find", logfields.WithPresDefID(pd.ID))

	if data.PresentationDefinitionFilters != nil {
		pd, err = applyPresentationDefinitionFilters(pd, data.PresentationDefinitionFilters)
		if err != nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "presentationDefinitionFilters", err)
		}

		logger.Debugc(ctx, "InitiateOidcInteraction applied filters to pd", logfields.WithPresDefID(pd.ID))
	}

	result, err := c.oidc4VPService.InitiateOidcInteraction(ctx, pd, strPtrToStr(data.Purpose), profile)
	if err != nil {
		return nil, resterr.NewSystemError("oidc4VPService", "InitiateOidcInteraction", err)
	}

	logger.Debugc(ctx, "InitiateOidcInteraction success", log.WithTxID(string(result.TxID)))
	return &InitiateOIDC4VPResponse{
		AuthorizationRequest: result.AuthorizationRequest,
		TxID:                 string(result.TxID),
	}, err
}

func applyPresentationDefinitionFilters(
	pd *presexch.PresentationDefinition,
	filters *PresentationDefinitionFilters,
) (*presexch.PresentationDefinition, error) {
	return applyFieldsFilter(pd, lo.FromPtr(filters.Fields))
}

func applyFieldsFilter(
	pd *presexch.PresentationDefinition,
	fields []string,
) (*presexch.PresentationDefinition, error) {
	var allMatchedFields []string
	for _, desc := range pd.InputDescriptors {
		var filteredFields []*presexch.Field

		var constraintsFields []string
		fieldMap := map[string]*presexch.Field{}
		for _, f := range desc.Constraints.Fields {
			constraintsFields = append(constraintsFields, f.ID)
			fieldMap[f.ID] = f
		}

		for _, field := range fields {
			matchedFieldID, matched, err := matchField(constraintsFields, field)
			if err != nil {
				return nil, err
			}

			if matched {
				filteredFields = append(filteredFields, fieldMap[matchedFieldID])
				allMatchedFields = append(allMatchedFields, field)
			}
		}

		desc.Constraints.Fields = filteredFields
	}

	for _, f := range fields {
		if !lo.Contains(allMatchedFields, f) {
			return nil, fmt.Errorf("field %v not found", f)
		}
	}

	return pd, nil
}

func matchField(ids []string, target string) (string, bool, error) {
	const wildcard = "*"

	for _, id := range ids {
		// this case covers both exact id and empty string rule
		if id == target {
			return id, true, nil
		}

		if strings.Contains(target, wildcard) {
			exp := strings.ReplaceAll(target, wildcard, "."+wildcard)
			r, err := regexp.Compile(exp)
			if err != nil {
				return "", false, fmt.Errorf("failed to compile regex=%s. %w", exp, err)
			}

			if r.MatchString(id) {
				return id, true, nil
			}
		}
	}

	return "", false, nil
}

// CheckAuthorizationResponse is used by verifier applications to initiate OpenID presentation flow through VCS.
// (POST /verifier/interactions/authorization-response).
func (c *Controller) CheckAuthorizationResponse(e echo.Context) error {
	logger.Debugc(e.Request().Context(), "CheckAuthorizationResponse begin")
	startTime := time.Now()

	ctx, span := c.tracer.Start(e.Request().Context(), "CheckAuthorizationResponse")
	defer span.End()

	defer func() {
		c.metrics.CheckAuthorizationResponseTime(time.Since(startTime))
		logger.Debugc(e.Request().Context(), "CheckAuthorizationResponse end",
			log.WithDuration(time.Since(startTime)))
	}()

	authResp, err := validateAuthorizationResponse(e)
	if err != nil {
		return err
	}

	processedTokens, err := c.verifyAuthorizationResponseTokens(ctx, authResp)
	if err != nil {
		return err
	}

	err = c.oidc4VPService.VerifyOIDCVerifiablePresentation(ctx, oidc4vp.TxID(authResp.State), processedTokens)
	if err != nil {
		return err
	}

	logger.Debugc(ctx, "CheckAuthorizationResponse succeed")

	return nil
}

// RetrieveInteractionsClaim is used by verifier applications to get claims obtained during oidc4vp interaction.
// (GET /verifier/interactions/{txID}/claim).
func (c *Controller) RetrieveInteractionsClaim(e echo.Context, txID string) error {
	logger.Debugc(e.Request().Context(), "RetrieveInteractionsClaim begin")

	ctx, span := c.tracer.Start(e.Request().Context(), "RetrieveInteractionsClaim")
	defer span.End()

	span.SetAttributes(attribute.String("tx_id", txID))

	tenantID, err := util.GetTenantIDFromRequest(e)
	if err != nil {
		return err
	}

	tx, err := c.accessOIDC4VPTx(ctx, txID)
	if err != nil {
		return err
	}

	_, err = c.accessProfile(tx.ProfileID, tx.ProfileVersion, tenantID)
	if err != nil {
		return err
	}

	if tx.ReceivedClaimsID == "" {
		return fmt.Errorf("claims were not received for transaction '%s'", txID)
	}

	if tx.ReceivedClaims == nil {
		return fmt.Errorf("claims are either retrieved or expired for transaction '%s'", txID)
	}

	claims := c.oidc4VPService.RetrieveClaims(ctx, tx)

	err = c.oidc4VPService.DeleteClaims(ctx, tx.ReceivedClaimsID)
	if err != nil {
		logger.Warnc(ctx, "RetrieveInteractionsClaim failed to delete claims", logfields.WithTransactionID(txID))
	}

	logger.Debugc(ctx, "RetrieveInteractionsClaim succeed")

	return util.WriteOutput(e)(claims, nil)
}

func (c *Controller) accessOIDC4VPTx(ctx context.Context, txID string) (*oidc4vp.Transaction, error) {
	tx, err := c.oidc4VPService.GetTx(ctx, oidc4vp.TxID(txID))

	if err != nil {
		if errors.Is(err, oidc4vp.ErrDataNotFound) {
			return nil, resterr.NewValidationError(resterr.DoesntExist, "txID",
				fmt.Errorf("transaction with given id %s, doesn't exist", txID))
		}

		return nil, resterr.NewSystemError(oidc4vpSvcComponent, "GetTx", err)
	}

	logger.Debugc(ctx, "RetrieveInteractionsClaim tx found", log.WithTxID(string(tx.ID)))

	return tx, nil
}

func (c *Controller) verifyAuthorizationResponseTokens(
	ctx context.Context,
	authResp *authorizationResponse,
) ([]*oidc4vp.ProcessedVPToken, error) {
	startTime := time.Now()
	defer func() {
		logger.Debugc(ctx, "validateResponseAuthTokens", log.WithDuration(time.Since(startTime)))
	}()

	idTokenClaims, err := validateIDToken(authResp.IDToken, c.jwtVerifier)
	if err != nil {
		return nil, err
	}

	logger.Debugc(ctx, "CheckAuthorizationResponse id_token verified")

	var processedVPTokens []*oidc4vp.ProcessedVPToken

	for _, vpToken := range authResp.VPToken {
		var vpTokenClaims *VPTokenClaims

		vpTokenClaims, err = c.validateRawVPToken(vpToken)
		if err != nil {
			return nil, err
		}

		logger.Debugc(ctx, "CheckAuthorizationResponse vp_token verified")

		// todo: consider to apply this validation for JWT VP in verifypresentation.Service
		if vpTokenClaims.Nonce != idTokenClaims.Nonce {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "nonce",
				errors.New("nonce should be the same for both id_token and vp_token"))
		}

		if vpTokenClaims.Aud != idTokenClaims.Aud {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "aud",
				errors.New("aud should be the same for both id_token and vp_token"))
		}

		logger.Debugc(ctx, "CheckAuthorizationResponse vp validated")

		if vpTokenClaims.VP.CustomFields == nil {
			vpTokenClaims.VP.CustomFields = map[string]interface{}{}
		}

		vpTokenClaims.VP.Context = append(vpTokenClaims.VP.Context, presexch.PresentationSubmissionJSONLDContextIRI)
		vpTokenClaims.VP.Type = append(vpTokenClaims.VP.Type, presexch.PresentationSubmissionJSONLDType)
		vpTokenClaims.VP.CustomFields[vpSubmissionProperty] = idTokenClaims.VPToken.PresentationSubmission

		processedVPTokens = append(processedVPTokens, &oidc4vp.ProcessedVPToken{
			Nonce:         idTokenClaims.Nonce,
			ClientID:      idTokenClaims.Aud,
			VpTokenFormat: vpTokenClaims.VpTokenFormat,
			Presentation:  vpTokenClaims.VP,
			SignerDIDID:   vpTokenClaims.SignerDIDID,
		})
	}

	return processedVPTokens, nil
}

func validateIDToken(idToken string, verifier jose.SignatureVerifier) (*IDTokenClaims, error) {
	_, rawClaims, err := jwt.Parse(idToken,
		jwt.WithSignatureVerifier(verifier),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "id_token", err)
	}

	var fastParser fastjson.Parser
	v, err := fastParser.ParseBytes(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	var presentationSubmission map[string]interface{}
	sb, err := v.Get("_vp_token", "presentation_submission").Object()
	if err == nil {
		if err = json.Unmarshal(sb.MarshalTo([]byte{}), &presentationSubmission); err != nil {
			return nil, fmt.Errorf("decode presentation_submission: %w", err)
		}
	}

	idTokenClaims := &IDTokenClaims{
		VPToken: IDTokenVPToken{
			PresentationSubmission: presentationSubmission,
		},
		Nonce: string(v.GetStringBytes("nonce")),
		Aud:   string(v.GetStringBytes("aud")),
		Exp:   v.GetInt64("exp"),
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

func (c *Controller) validateRawVPToken(vpToken string) (*VPTokenClaims, error) {
	if jwt.IsJWS(vpToken) {
		return c.validateVPTokenJWT(vpToken)
	}

	return c.validateVPTokenLDP(vpToken)
}

func (c *Controller) validateVPTokenJWT(vpToken string) (*VPTokenClaims, error) {
	jsonWebToken, rawClaims, err := jwt.Parse(vpToken,
		jwt.WithSignatureVerifier(c.jwtVerifier),
		jwt.WithIgnoreClaimsMapDecoding(true))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token", err)
	}

	var fastParser fastjson.Parser
	v, err := fastParser.ParseBytes(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	exp := v.GetInt64("exp")
	if exp < time.Now().Unix() {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.exp", fmt.Errorf(
			"token expired"))
	}

	presentation, err := verifiable.ParsePresentation([]byte(vpToken),
		verifiable.WithPresJSONLDDocumentLoader(c.documentLoader),
		verifiable.WithPresPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(c.vdr).PublicKeyFetcher(),
		))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.vp", err)
	}

	// Do not need to check since is has passed jwt.Parse().
	kid, _ := jsonWebToken.Headers.KeyID()

	return &VPTokenClaims{
		Nonce:         string(v.GetStringBytes("nonce")),
		Aud:           string(v.GetStringBytes("aud")),
		SignerDIDID:   strings.Split(kid, "#")[0],
		VpTokenFormat: vcsverifiable.Jwt,
		VP:            presentation,
	}, nil
}

func (c *Controller) validateVPTokenLDP(vpToken string) (*VPTokenClaims, error) {
	presentation, err := verifiable.ParsePresentation([]byte(vpToken),
		verifiable.WithPresJSONLDDocumentLoader(c.documentLoader),
		verifiable.WithPresPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(c.vdr).PublicKeyFetcher(),
		))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.vp", err)
	}

	verificationMethod, err := crypto.GetVerificationMethodFromProof(presentation.Proofs[0])
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.verificationMethod", err)
	}

	didID, err := diddoc.GetDIDFromVerificationMethod(verificationMethod)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.didID", err)
	}

	nonce, ok := presentation.Proofs[0]["challenge"].(string)
	if !ok {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.challenge", errMissedField)
	}

	clientID, ok := presentation.Proofs[0]["domain"].(string)
	if !ok {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.domain", errMissedField)
	}

	return &VPTokenClaims{
		Nonce:         nonce,
		SignerDIDID:   didID,
		Aud:           clientID,
		VpTokenFormat: vcsverifiable.Ldp,
		VP:            presentation,
	}, nil
}

func validateAuthorizationResponse(ctx echo.Context) (*authorizationResponse, error) {
	startTime := time.Now().UTC()
	defer func() {
		logger.Debugc(ctx.Request().Context(),
			"validateAuthorizationResponse", log.WithDuration(time.Since(startTime)))
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

	logger.Debugc(ctx.Request().Context(),
		"AuthorizationResponse id_token decoded", logfields.WithIDToken(res.IDToken))

	var vpTokenStr string

	err = decodeFormValue(&vpTokenStr, "vp_token", req.PostForm)
	if err != nil {
		return nil, err
	}

	res.VPToken = getVPTokens(vpTokenStr)

	logger.Debugc(ctx.Request().Context(), "AuthorizationResponse vp_token decoded")

	err = decodeFormValue(&res.State, "state", req.PostForm)
	if err != nil {
		return nil, err
	}

	logger.Debugc(ctx.Request().Context(), "AuthorizationResponse state decoded", log.WithState(res.State))

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

func (c *Controller) accessProfile(profileID, profileVersion, tenantID string) (*profileapi.Verifier, error) {
	profile, err := c.profileSvc.GetProfile(profileID, profileVersion)
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

	if pdExternalID == "" && len(pds) == 1 {
		return copyPresentationDefinition(pds[0])
	}

	for _, pd := range pds {
		if pd.ID == pdExternalID {
			return copyPresentationDefinition(pd)
		}
	}

	return nil, fmt.Errorf("presentation definition id=%s not found for profile with id=%s", pdExternalID, profile.ID)
}

func copyPresentationDefinition(pd *presexch.PresentationDefinition) (*presexch.PresentationDefinition, error) {
	b, err := json.Marshal(pd)
	if err != nil {
		return nil, fmt.Errorf("marshal pd: %w", err)
	}

	var copyPD *presexch.PresentationDefinition
	if err = json.Unmarshal(b, &copyPD); err != nil {
		return nil, fmt.Errorf("unmarshal pd: %w", err)
	}

	return copyPD, nil
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
