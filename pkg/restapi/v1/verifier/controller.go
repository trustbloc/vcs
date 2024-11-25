/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package verifier -source=controller.go -mock_names profileService=MockProfileService,verifyCredentialSvc=MockVerifyCredentialService,kmsRegistry=MockKMSRegistry,oidc4VPService=MockOIDC4VPService

package verifier

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/suite/ecdsa2019"
	"github.com/trustbloc/vc-go/dataintegrity/suite/eddsa2022"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vc-go/vermethod"
	"github.com/valyala/fastjson"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/doc/vp"
	"github.com/trustbloc/vcs/pkg/event/spi"
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
	vpSubmissionProperty = "presentation_submission"
)

var (
	logger         = log.New("oidc4vp")
	errMissedField = errors.New("missed field")
)

type rawAuthorizationResponse struct {
	IDToken                string
	VPToken                []string
	PresentationSubmission string
	Error                  string
	ErrorDescription       string
	State                  string
	InteractionDetails     map[string]interface{}
}

type IDTokenClaims struct {
	// CustomScopeClaims stores claims retrieved using custom scope.
	CustomScopeClaims map[string]oidc4vp.Claims `json:"_scope,omitempty"`
	AttestationVP     string                    `json:"_attestation_vp"`
	Nonce             string                    `json:"nonce"`
	Aud               string                    `json:"aud"`
	Exp               int64                     `json:"exp"`
	Attachments       map[string]string         `json:"_attachments"`
}

type VPTokenClaims struct {
	Nonce         string                   `json:"nonce"`
	Aud           string                   `json:"aud"`
	Iss           string                   `json:"iss"`
	Exp           int64                    `json:"exp"`
	SignerDIDID   string                   `json:"signer_did_id"`
	VpTokenFormat vcsverifiable.Format     `json:"vp_token_format"`
	VP            *verifiable.Presentation `json:"vp"`
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

type eventService interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type Config struct {
	VerifyCredentialSvc   verifyCredentialSvc
	VerifyPresentationSvc verifyPresentationSvc
	ProfileSvc            profileService
	KMSRegistry           kmsRegistry
	DocumentLoader        ld.DocumentLoader
	VDR                   vdrapi.Registry
	OIDCVPService         oidc4VPService
	ProofChecker          verifiable.CombinedProofChecker
	Metrics               metricsProvider
	Tracer                trace.Tracer
	EventSvc              eventService
	EventTopic            string
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
	oidc4VPService        oidc4VPService
	proofChecker          verifiable.CombinedProofChecker
	metrics               metricsProvider
	tracer                trace.Tracer
	eventSvc              eventService
	eventTopic            string
	vdr                   vdrapi.Registry
}

// NewController creates a new controller for Verifier Profile Management API.
func NewController(config *Config) *Controller {
	if config.ProofChecker == nil {
		config.ProofChecker = defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(config.VDR))
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
		oidc4VPService:        config.OIDCVPService,
		proofChecker:          config.ProofChecker,
		metrics:               metrics,
		tracer:                config.Tracer,
		eventSvc:              config.EventSvc,
		eventTopic:            config.EventTopic,
		vdr:                   config.VDR,
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

	if body.VerifiableCredential == nil && body.Credential != nil {
		body.VerifiableCredential = body.Credential
	}

	tenantID, err := util.GetTenantIDFromRequest(e)
	if err != nil {
		return err
	}

	resp, err := c.verifyCredential(ctx, &body, profileID, profileVersion, tenantID)
	if err != nil {
		return err
	}

	hasErrors := false
	if resp.Checks != nil {
		for _, check := range *resp.Checks {
			if check.Error != "" {
				hasErrors = true
				break
			}
		}
	}

	if hasErrors {
		return util.WriteOutputWithCode(http.StatusBadRequest, e)(resp, nil)
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
	if body.VerifiableCredential == nil && body.Credential != nil {
		body.VerifiableCredential = body.Credential
	}

	if body.VerifiableCredential == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential",
			errors.New("missing credential"))
	}

	profile, err := c.accessProfile(profileID, profileVersion, tenantID)
	if err != nil {
		return nil, err
	}

	credential, err := vc.ValidateCredential(
		ctx,
		*body.VerifiableCredential,
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
		return nil, resterr.NewSystemError(resterr.VerifierVerifyCredentialSvcComponent, "VerifyCredential", err)
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

	tenantID, err := util.GetTenantIDFromRequest(e)
	if err != nil {
		return err
	}

	resp, err := c.verifyPresentation(ctx, &body, profileID, profileVersion, tenantID)
	if err != nil {
		return err
	}

	if len(lo.FromPtr(resp.Errors)) > 0 {
		return util.WriteOutputWithCode(http.StatusBadRequest, e)(resp, nil)
	}

	return util.WriteOutput(e)(resp, nil)
}

func (c *Controller) verifyPresentation(
	ctx context.Context,
	body *VerifyPresentationData,
	profileID string,
	profileVersion string,
	tenantID string,
) (*VerifyPresentationResponse, error) {
	profile, err := c.accessProfile(profileID, profileVersion, tenantID)
	if err != nil {
		return nil, err
	}

	dataVerifier, err := c.getDataIntegrityVerifier()
	if err != nil {
		return nil, resterr.NewSystemError(resterr.VerifierPresentationVerifierComponent,
			"VerifyPresentation", err)
	}

	opts := []verifiable.PresentationOpt{
		verifiable.WithPresProofChecker(c.proofChecker),
		verifiable.WithPresJSONLDDocumentLoader(c.documentLoader),
		verifiable.WithPresDataIntegrityVerifier(dataVerifier),
		verifiable.WithPresHolderCheck(true),
	}

	if body.Options != nil {
		opts = append(opts, verifiable.WithPresExpectedDataIntegrityFields(
			"authentication",
			lo.FromPtr(body.Options.Domain),
			lo.FromPtr(body.Options.Challenge),
		))
	}

	presentation, err := vp.ValidatePresentation(
		body.VerifiablePresentation,
		profile.Checks.Presentation.Format,
		opts...,
	)

	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "presentation", err)
	}

	verRes, _, err := c.verifyPresentationSvc.VerifyPresentation(
		ctx,
		presentation,
		getVerifyPresentationOptions(body.Options),
		profile,
	)

	if err != nil {
		return nil, resterr.NewSystemError(resterr.VerifierVerifyCredentialSvcComponent, "VerifyCredential", err)
	}

	logger.Debugc(ctx, "PostVerifyPresentation completed")

	return mapVerifyPresentationChecks(verRes, presentation), nil
}

func (c *Controller) getDataIntegrityVerifier() (*dataintegrity.Verifier, error) {
	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: c.vdr,
	}, eddsa2022.NewVerifierInitializer(&eddsa2022.VerifierInitializerOptions{
		LDDocumentLoader: c.documentLoader,
	}), ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: c.documentLoader,
	}))
	if err != nil {
		return nil, fmt.Errorf("new verifier: %w", err)
	}

	return verifier, nil
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
	if profile.OIDCConfig == nil {
		return nil, resterr.NewValidationError(resterr.ConditionNotMet, "profile.OIDCConfig",
			errors.New("OIDC not configured"))
	}

	pd, err := findPresentationDefinition(
		profile,
		lo.FromPtr(data.PresentationDefinitionId),
		data,
	)
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

	result, err := c.oidc4VPService.InitiateOidcInteraction(
		ctx, pd, lo.FromPtr(data.Purpose), lo.FromPtr(data.Scopes), lo.FromPtr(data.CustomURLScheme), profile)
	if err != nil {
		return nil, resterr.NewSystemError(resterr.VerifierOIDC4vpSvcComponent, "InitiateOidcInteraction", err)
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

	rawAuthResp, err := decodeAuthorizationResponse(e)
	if err != nil {
		return err
	}

	if rawAuthResp.Error != "" {
		// Error authorization response
		// Spec: https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#section-6.4
		return c.oidc4VPService.HandleWalletNotification(ctx, &oidc4vp.WalletNotification{
			TxID:               oidc4vp.TxID(rawAuthResp.State),
			Error:              rawAuthResp.Error,
			ErrorDescription:   rawAuthResp.ErrorDescription,
			InteractionDetails: rawAuthResp.InteractionDetails,
		})
	}

	responseParsed, err := c.verifyAuthorizationResponseTokens(ctx, rawAuthResp)
	if err != nil {
		if tenantID, authErr := util.GetTenantIDFromRequest(e); authErr == nil {
			c.sendFailedEvent(ctx, rawAuthResp.State, tenantID, "", "", err)
		}

		return err
	}

	err = c.oidc4VPService.VerifyOIDCVerifiablePresentation(ctx, oidc4vp.TxID(rawAuthResp.State), responseParsed)
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
		c.sendFailedEvent(ctx, txID, tenantID, "", "", err)

		return err
	}

	profile, err := c.accessProfile(tx.ProfileID, tx.ProfileVersion, tenantID)
	if err != nil {
		c.sendFailedTxnEvent(ctx, tenantID, tx, err)

		return err
	}

	if tx.ReceivedClaimsID == "" {
		err = resterr.NewCustomError(resterr.ClaimsNotReceived,
			fmt.Errorf("claims were not received for transaction '%s'", txID))

		c.sendFailedTxnEvent(ctx, tenantID, tx, err)

		return err
	}

	if tx.ReceivedClaims == nil {
		err = resterr.NewCustomError(resterr.ClaimsNotFound,
			fmt.Errorf("claims are either retrieved or expired for transaction '%s'", txID))

		c.sendFailedTxnEvent(ctx, tenantID, tx, err)

		return err
	}

	claims := c.oidc4VPService.RetrieveClaims(ctx, tx, profile)

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
			return nil, resterr.NewCustomError(resterr.TransactionNotFound,
				fmt.Errorf("transaction with given id %s, doesn't exist", txID))
		}

		return nil, resterr.NewSystemError(resterr.VerifierOIDC4vpSvcComponent, "GetTx", err)
	}

	logger.Debugc(ctx, "RetrieveInteractionsClaim tx found", log.WithTxID(string(tx.ID)))

	return tx, nil
}

func (c *Controller) verifyAuthorizationResponseTokens(
	ctx context.Context,
	authResp *rawAuthorizationResponse,
) (*oidc4vp.AuthorizationResponseParsed, error) {
	startTime := time.Now()
	defer func() {
		logger.Debugc(ctx, "validateResponseAuthTokens", log.WithDuration(time.Since(startTime)))
	}()

	var presentationSubmission map[string]interface{}

	if authResp.PresentationSubmission != "" {
		if err := json.Unmarshal([]byte(authResp.PresentationSubmission), &presentationSubmission); err != nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "presentation_submission", err)
		}
	}

	idTokenClaims, err := validateIDToken(authResp.IDToken, &presentationSubmission, c.proofChecker)
	if err != nil {
		return nil, err
	}

	if presentationSubmission == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "presentation_submission",
			fmt.Errorf("presentation_submission is missed"))
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

		if !lo.Contains(vpTokenClaims.VP.Context, presexch.PresentationSubmissionJSONLDContextIRI) {
			vpTokenClaims.VP.Context = append(vpTokenClaims.VP.Context, presexch.PresentationSubmissionJSONLDContextIRI)
		}

		if !lo.Contains(vpTokenClaims.VP.Type, presexch.PresentationSubmissionJSONLDType) {
			vpTokenClaims.VP.Type = append(vpTokenClaims.VP.Type, presexch.PresentationSubmissionJSONLDType)
		}

		vpTokenClaims.VP.CustomFields[vpSubmissionProperty] = presentationSubmission

		processedVPTokens = append(processedVPTokens,
			&oidc4vp.ProcessedVPToken{
				Nonce:         idTokenClaims.Nonce,
				ClientID:      idTokenClaims.Aud,
				VpTokenFormat: vpTokenClaims.VpTokenFormat,
				Presentation:  vpTokenClaims.VP,
				SignerDIDID:   vpTokenClaims.SignerDIDID,
			},
		)
	}

	return &oidc4vp.AuthorizationResponseParsed{
		CustomScopeClaims:  idTokenClaims.CustomScopeClaims,
		VPTokens:           processedVPTokens,
		AttestationVP:      idTokenClaims.AttestationVP,
		Attachments:        idTokenClaims.Attachments,
		InteractionDetails: authResp.InteractionDetails,
	}, nil
}

func validateIDToken(
	idTokenJWT string,
	presentationSubmission *map[string]interface{},
	verifier jwt.ProofChecker,
) (*IDTokenClaims, error) {
	_, rawClaims, err := jwt.ParseAndCheckProof(
		idTokenJWT,
		verifier,
		false,
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "id_token", err)
	}

	var parser fastjson.Parser

	v, err := parser.ParseBytes(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("decode id_token claims: %w", err)
	}

	var customScopeClaims map[string]oidc4vp.Claims

	if val := v.Get("_scope"); val != nil {
		var obj *fastjson.Object

		obj, err = val.Object()
		if err == nil {
			if err = json.Unmarshal(obj.MarshalTo([]byte{}), &customScopeClaims); err != nil {
				return nil, fmt.Errorf("decode _scope: %w", err)
			}
		}
	}

	if val := v.Get("_vp_token", "presentation_submission"); val != nil { // _vp_token is obsolete
		var obj *fastjson.Object

		obj, err = v.Get("_vp_token", "presentation_submission").Object()
		if err == nil {
			if err = json.Unmarshal(obj.MarshalTo([]byte{}), &presentationSubmission); err != nil {
				return nil, fmt.Errorf("decode presentation_submission: %w", err)
			}
		}
	}

	idTokenClaims := &IDTokenClaims{
		CustomScopeClaims: customScopeClaims,
		AttestationVP:     string(v.GetStringBytes("_attestation_vp")),
		Nonce:             string(v.GetStringBytes("nonce")),
		Aud:               string(v.GetStringBytes("aud")),
		Exp:               v.GetInt64("exp"),
		Attachments:       map[string]string{},
	}

	if val := v.Get("_attachments"); val != nil {
		o, _ := val.Object() //nolint

		if o != nil {
			o.Visit(func(k []byte, v *fastjson.Value) {
				idTokenClaims.Attachments[string(k)] = string(v.GetStringBytes())
			})
		}
	}

	if idTokenClaims.Exp < time.Now().Unix() {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "id_token.exp", fmt.Errorf("token expired"))
	}

	return idTokenClaims, nil
}

func (c *Controller) validateRawVPToken(vpToken string) (*VPTokenClaims, error) {
	if jwt.IsJWS(vpToken) {
		return c.validateVPTokenJWT(vpToken)
	}

	return c.validateVPToken(vpToken)
}

func (c *Controller) validateVPTokenJWT(vpToken string) (*VPTokenClaims, error) {
	jsonWebToken, rawClaims, err := jwt.ParseAndCheckProof(vpToken,
		c.proofChecker, true,
		jwt.WithIgnoreClaimsMapDecoding(true))
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token", err)
	}

	var parser fastjson.Parser
	v, err := parser.ParseBytes(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("decode vp token claims: %w", err)
	}

	exp := v.GetInt64("exp")
	if exp < time.Now().Unix() {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.exp",
			fmt.Errorf("token expired"))
	}

	presentation, err := verifiable.ParsePresentation([]byte(vpToken),
		verifiable.WithPresJSONLDDocumentLoader(c.documentLoader),
		verifiable.WithPresProofChecker(c.proofChecker),
	)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.vp", err)
	}

	// Do not need to check err since token has passed jwt.Parse().
	kid, _ := jsonWebToken.Headers.KeyID()

	return &VPTokenClaims{
		Nonce:         string(v.GetStringBytes("nonce")),
		Aud:           string(v.GetStringBytes("aud")),
		SignerDIDID:   strings.Split(kid, "#")[0],
		VpTokenFormat: vcsverifiable.Jwt,
		VP:            presentation,
	}, nil
}

func (c *Controller) validateVPTokenCWT(
	presentation *verifiable.Presentation,
) (*VPTokenClaims, error) {
	if presentation.CWT == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.vp",
			errors.New("cwt presentation is missed"))
	}
	if len(presentation.CWT.VPMap) == 0 {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.vp",
			errors.New("cwt vp map is empty"))
	}
	if presentation.CWT.Message == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.vp",
			errors.New("cwt message is missed"))
	}

	return &VPTokenClaims{
		Nonce:         fmt.Sprint(presentation.CWT.VPMap["nonce"]),
		Aud:           fmt.Sprint(presentation.CWT.VPMap["aud"]),
		SignerDIDID:   strings.Split(fmt.Sprint(presentation.CWT.VPMap["iss"]), "#")[0],
		VpTokenFormat: vcsverifiable.Cwt,
		VP:            presentation,
	}, nil
}

func (c *Controller) validateVPToken(vpToken string) (*VPTokenClaims, error) {
	presentation, err := verifiable.ParsePresentation([]byte(vpToken),
		verifiable.WithPresJSONLDDocumentLoader(c.documentLoader),
		verifiable.WithPresProofChecker(c.proofChecker),
	)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "vp_token.vp", err)
	}

	if presentation.CWT != nil {
		return c.validateVPTokenCWT(presentation)
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

func decodeAuthorizationResponse(ctx echo.Context) (*rawAuthorizationResponse, error) {
	startTime := time.Now().UTC()

	defer func() {
		logger.Debugc(ctx.Request().Context(), "decodeAuthorizationResponse", log.WithDuration(time.Since(startTime)))
	}()

	req := ctx.Request()

	contentType := req.Header.Get("Content-Type")

	if contentType != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("content type is not application/x-www-form-urlencoded")
	}

	err := req.ParseForm()
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "body", err)
	}

	res := &rawAuthorizationResponse{}

	err = decodeFormValue(&res.State, "state", req.PostForm)
	if err != nil {
		return nil, err
	}

	var rawInteractionDetails string
	err = decodeFormValue(&rawInteractionDetails, "interaction_details", req.PostForm)
	if err == nil {
		var rawInteractionDetailsBytes []byte

		rawInteractionDetailsBytes, err = base64.StdEncoding.DecodeString(rawInteractionDetails)
		if err != nil {
			return nil, resterr.NewValidationError(
				resterr.InvalidValue,
				"interaction_details",
				fmt.Errorf("base64 decode: %w", err))
		}

		err = json.Unmarshal(rawInteractionDetailsBytes, &res.InteractionDetails)
		if err != nil {
			return nil, resterr.NewValidationError(
				resterr.InvalidValue,
				"interaction_details",
				fmt.Errorf("json decode: %w", err))
		}
	}

	err = decodeFormValue(&res.Error, "error", req.PostForm)
	if err == nil {
		// Error authorization response
		// Spec: https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#section-6.4
		err = decodeFormValue(&res.ErrorDescription, "error_description", req.PostForm)
		if err != nil {
			return nil, err
		}

		return res, nil
	}

	logger.Debugc(ctx.Request().Context(), "AuthorizationResponse state decoded", log.WithState(res.State))

	err = decodeFormValue(&res.IDToken, "id_token", req.PostForm)
	if err != nil {
		return nil, err
	}

	logger.Debugc(ctx.Request().Context(), "AuthorizationResponse id_token decoded",
		logfields.WithIDToken(res.IDToken))

	var vpTokenStr string

	err = decodeFormValue(&vpTokenStr, "vp_token", req.PostForm)
	if err != nil {
		return nil, err
	}

	res.VPToken = getVPTokens(vpTokenStr)

	logger.Debugc(ctx.Request().Context(), "AuthorizationResponse vp_token decoded")

	if req.PostForm.Has("presentation_submission") {
		err = decodeFormValue(&res.PresentationSubmission, "presentation_submission", req.PostForm)
		if err != nil {
			return nil, err
		}
	}

	logger.Debugc(ctx.Request().Context(), "AuthorizationResponse presentation_submission decoded",
		log.WithState(res.State))

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
			return nil, resterr.NewCustomError(resterr.ProfileNotFound,
				fmt.Errorf("profile with given id %q, doesn't exist", profileID))
		}

		return nil, resterr.NewSystemError(resterr.VerifierProfileSvcComponent, "GetProfile", err)
	}

	if profile == nil {
		return nil, resterr.NewCustomError(resterr.ProfileNotFound,
			fmt.Errorf("profile with given id %q, doesn't exist", profileID))
	}

	// Profiles of other organization is not visible.
	if profile.OrganizationID != tenantID {
		return nil, resterr.NewCustomError(resterr.ProfileNotFound,
			fmt.Errorf("profile with given org id %q, doesn't exist", tenantID))
	}

	return profile, nil
}

func createFailedEventPayload(orgID, profileID, profileVersion string, e error) *oidc4vp.EventPayload {
	ep := &oidc4vp.EventPayload{
		OrgID:          orgID,
		ProfileID:      profileID,
		ProfileVersion: profileVersion,
	}

	ep.Error, ep.ErrorCode, ep.ErrorComponent = resterr.GetErrorDetails(e)

	return ep
}

func (c *Controller) sendFailedEvent(ctx context.Context, txnID, orgID, profileID, profileVersion string, e error) {
	c.sendOIDCInteractionFailedEvent(ctx, oidc4vp.TxID(txnID), func() *oidc4vp.EventPayload {
		return createFailedEventPayload(orgID, profileID, profileVersion, e)
	})
}

func (c *Controller) sendFailedTxnEvent(ctx context.Context, orgID string, tx *oidc4vp.Transaction, e error) {
	c.sendOIDCInteractionFailedEvent(ctx, tx.ID, func() *oidc4vp.EventPayload {
		ep := createFailedEventPayload(orgID, tx.ProfileID, tx.ProfileVersion, e)
		ep.PresentationDefinitionID = tx.PresentationDefinition.ID

		return ep
	})
}

func (c *Controller) sendOIDCInteractionFailedEvent(
	ctx context.Context,
	txnID oidc4vp.TxID,
	createPayload func() *oidc4vp.EventPayload,
) {
	evt, err := oidc4vp.CreateEvent(spi.VerifierOIDCInteractionFailed, txnID, createPayload())
	if err != nil {
		logger.Errorc(ctx, "Error creating failure event", log.WithError(err))

		return
	}

	err = c.eventSvc.Publish(ctx, c.eventTopic, evt)
	if err != nil {
		logger.Errorc(ctx, "Error publishing failure event", log.WithError(err))

		return
	}
}

func findPresentationDefinition(
	profile *profileapi.Verifier,
	pdExternalID string,
	data *InitiateOIDC4VPData,
) (*presexch.PresentationDefinition, error) {
	pds := profile.PresentationDefinitions

	if pdExternalID == "" && len(pds) == 1 {
		return copyPresentationDefinition(pds[0])
	}

	for _, pd := range pds {
		if pd.ID == pdExternalID {
			return copyPresentationDefinition(pd)
		}
	}

	if profile.OIDCConfig != nil && profile.OIDCConfig.DynamicPresentationSupported {
		return addDynamicPresentation(pdExternalID, data)
	}

	return nil, fmt.Errorf("presentation definition id=%s not found for profile with id=%s",
		pdExternalID, profile.ID)
}

func addDynamicPresentation(id string, data *InitiateOIDC4VPData) (*presexch.PresentationDefinition, error) {
	if data == nil || data.DynamicPresentationFilters == nil {
		return nil, errors.New("dynamic presentation filters should be specified for dynamic presentation")
	}

	var fields []*presexch.Field

	if len(lo.FromPtr(data.DynamicPresentationFilters.Context)) > 0 {
		field := &presexch.Field{
			Path: []string{
				"$['@context']",
			},
			ID: "filter_context",
			Filter: &presexch.Filter{
				FilterItem: presexch.FilterItem{
					Type: lo.ToPtr("array"),
				},
			},
		}

		for _, ctx := range lo.FromPtr(data.DynamicPresentationFilters.Context) {
			field.Filter.AllOf = append(field.Filter.AllOf, &presexch.FilterItem{
				Contains: map[string]interface{}{
					"const": ctx,
					"type":  "string",
				},
			})
		}

		fields = append(fields, field)
	}

	if lo.FromPtr(data.DynamicPresentationFilters.Type) != "" {
		fields = append(fields, &presexch.Field{
			Path: []string{
				"$['type']",
			},
			ID: "filter_type",
			Filter: &presexch.Filter{
				FilterItem: presexch.FilterItem{
					Type: lo.ToPtr("array"),
				},
				AllOf: []*presexch.FilterItem{
					{
						Contains: map[string]interface{}{
							"const": lo.FromPtr(data.DynamicPresentationFilters.Type),
							"type":  "string",
						},
					},
				},
			},
		})
	}

	inputFields := []string{"dynamic_id"}
	inputFieldsAreEmpty := true

	if data.PresentationDefinitionFilters != nil {
		defFields := lo.FromPtr(data.PresentationDefinitionFilters.Fields)

		if len(defFields) > 0 {
			inputFields = defFields
			inputFieldsAreEmpty = false
		}
	}

	for i, fieldID := range inputFields {
		if i >= len(fields) {
			break
		}

		fields[i].ID = fieldID
	}

	if data.PresentationDefinitionFilters != nil && inputFieldsAreEmpty {
		data.PresentationDefinitionFilters.Fields = &inputFields
	}

	return &presexch.PresentationDefinition{
		ID:   id,
		Name: "dynamic",
		InputDescriptors: []*presexch.InputDescriptor{
			{
				ID: "dynamic-0",
				Constraints: &presexch.Constraints{
					Fields: fields,
				},
			},
		},
	}, nil
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
	result verifypresentation.PresentationVerificationResult,
	pres *verifiable.Presentation,
) *VerifyPresentationResponse {
	final := &VerifyPresentationResponse{
		Checks:             nil,
		Errors:             nil,
		PresentationResult: PresentationResult{}, // vcplayground
		Warnings:           nil,
	}

	var errArr []string

	for _, check := range result.Checks {
		final.Checks = append(final.Checks, check.Check)

		if check.Error != nil {
			errArr = append(errArr, check.Error.Error())
		}
	}

	if len(errArr) > 0 {
		final.Errors = &errArr
	}

	final.PresentationResult.Verified = len(errArr) == 0 // vcplayeground
	final.Verified = final.PresentationResult.Verified   // vcplayeground

	if final.PresentationResult.Verified && pres != nil {
		for range pres.Credentials() {
			final.CredentialResults = append(final.CredentialResults, PresentationResult{ // vcplayeground
				Verified: true,
			})
		}
	}

	return final
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
