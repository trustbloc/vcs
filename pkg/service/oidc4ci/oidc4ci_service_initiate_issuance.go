/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/jwt"
	verifiable2 "github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4cierr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4ci"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

const (
	TxCodeLength = 6

	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypePreAuthorizedCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// InitiateIssuance creates credential issuance transaction and builds initiate issuance URL.
func (s *Service) InitiateIssuance( // nolint:funlen,gocyclo,gocognit
	ctx context.Context,
	req *InitiateIssuanceRequest,
	profile *profileapi.Issuer,
) (*InitiateIssuanceResponse, error) { // *oidc4cierr.Error
	if req.OpState == "" {
		req.OpState = uuid.NewString()
	}

	if profile.VCConfig == nil {
		return nil, oidc4cierr.NewBadRequestError(ErrVCOptionsNotConfigured)
	}

	// Apply default GrantType for backward compatability.
	if req.GrantType == "" {
		req.GrantType = GrantTypePreAuthorizedCode
	}

	if req.GrantType != GrantTypeAuthorizationCode && req.GrantType != GrantTypePreAuthorizedCode {
		return nil, oidc4cierr.NewBadRequestError(
			fmt.Errorf("unexpected grant_type supplied %s", req.GrantType)).
			WithIncorrectValue("grant_type")
	}

	isPreAuthFlow := req.GrantType == GrantTypePreAuthorizedCode
	if !isPreAuthFlow && profile.OIDCConfig == nil {
		return nil, oidc4cierr.NewBadRequestError(ErrAuthorizedCodeFlowNotSupported)
	}

	issuedCredentialConfiguration := make(
		[]*issuecredential.TxCredentialConfiguration,
		0,
		len(req.CredentialConfiguration),
	)

	for _, credentialConfiguration := range req.CredentialConfiguration {
		txCredentialConf, err := s.newTxCredentialConf(
			ctx, credentialConfiguration, isPreAuthFlow, profile)
		if err != nil {
			return nil, err
		}

		issuedCredentialConfiguration = append(issuedCredentialConfiguration, txCredentialConf)
	}

	txState := issuecredential.TransactionStateIssuanceInitiated
	if req.WalletInitiatedIssuance {
		txState = issuecredential.TransactionStateAwaitingIssuerOIDCAuthorization
	}

	opState := req.OpState

	var preAuthCode string
	if isPreAuthFlow {
		preAuthCode = generatePreAuthCode()
		opState = preAuthCode // set opState as it will be empty for pre-auth
	}

	txData := &issuecredential.TransactionData{
		ProfileID:               profile.ID,
		ProfileVersion:          profile.Version,
		OrgID:                   profile.OrganizationID,
		ResponseType:            req.ResponseType,
		State:                   txState,
		WebHookURL:              profile.WebHook,
		RefreshServiceEnabled:   profile.VCConfig.RefreshServiceEnabled,
		DID:                     profile.SigningDID.DID,
		WalletInitiatedIssuance: req.WalletInitiatedIssuance,
		IsPreAuthFlow:           isPreAuthFlow,
		PreAuthCode:             preAuthCode,
		OpState:                 opState,
		CredentialConfiguration: issuedCredentialConfiguration,
	}

	var err *oidc4cierr.Error
	if err = s.extendTransactionWithOIDCConfig(ctx, profile, txData); err != nil {
		return nil, err
	}

	if err = setGrantType(txData, profile.OIDCConfig.GrantTypesSupported, req.GrantType); err != nil {
		return nil, err
	}

	if err = setScopes(txData, profile.OIDCConfig.ScopesSupported, req.Scope); err != nil {
		return nil, err
	}

	if txData.ResponseType == "" {
		txData.ResponseType = defaultResponseType
	}

	if req.UserPinRequired {
		txData.UserPin = s.pinGenerator.Generate(uuid.NewString())
	}

	tx, storeCreateErr := s.store.Create(ctx, profile.DataConfig.OIDC4CITransactionDataTTL, txData)
	if storeCreateErr != nil {
		return nil, oidc4cierr.NewBadRequestError(storeCreateErr).
			WithErrorPrefix("store tx").
			WithComponent(resterr.TransactionStoreComponent).
			WithOperation("create")
	}

	finalURL, contentType, err := s.buildInitiateIssuanceURL(ctx, req, tx, profile)
	if err != nil {
		return nil, err
	}

	if errSendEvent := s.sendInitiateIssuanceEvent(ctx, tx, finalURL); errSendEvent != nil {
		return nil, oidc4cierr.NewBadRequestError(errSendEvent).
			WithErrorPrefix("send initiate issuance event")
	}

	return &InitiateIssuanceResponse{
		InitiateIssuanceURL: finalURL,
		TxID:                tx.ID,
		UserPin:             tx.UserPin,
		Tx:                  tx,
		ContentType:         contentType,
	}, nil
}

func (s *Service) validateFlowSpecificRequestParams(
	isPreAuthFlow bool,
	req InitiateIssuanceCredentialConfiguration,
) *oidc4cierr.Error {
	if isPreAuthFlow {
		if len(req.ClaimData) == 0 && (req.ComposeCredential == nil || req.ComposeCredential.Credential == nil) {
			return oidc4cierr.NewBadRequestError(
				errors.New("claim_data param is not supplied")).
				WithIncorrectValue("claim_data")
		}
	} else {
		if len(req.ClaimEndpoint) == 0 {
			return oidc4cierr.NewBadRequestError(
				errors.New("claim_endpoint param is not supplied")).
				WithIncorrectValue("claim_data")
		}
	}

	return nil
}

func (s *Service) newTxCredentialConf(
	ctx context.Context,
	credentialConfiguration InitiateIssuanceCredentialConfiguration,
	isPreAuthFlow bool,
	profile *profileapi.Issuer,
) (*issuecredential.TxCredentialConfiguration, *oidc4cierr.Error) {
	err := s.validateFlowSpecificRequestParams(
		isPreAuthFlow,
		credentialConfiguration,
	)
	if err != nil {
		return nil, err
	}

	var targetCredentialTemplate *profileapi.CredentialTemplate

	isCompose := credentialConfiguration.ComposeCredential != nil &&
		credentialConfiguration.ComposeCredential.Credential != nil

	if credentialConfiguration.CredentialTemplateID == "" && isCompose { //nolint:nestif
		targetCredentialTemplate = s.buildVirtualTemplate(&credentialConfiguration)

		if targetCredentialTemplate.Checks.Strict { //nolint:nestif
			if err = s.validateComposeCredential(*credentialConfiguration.ComposeCredential.Credential); err != nil {
				return nil, err
			}
		}
	} else {
		targetCredentialTemplate, err = findCredentialTemplate(credentialConfiguration.CredentialTemplateID, profile)
		if err != nil {
			return nil, err
		}
	}

	credentialConfigurationID, metaCredentialConfiguration, err := s.findCredentialConfigurationID(
		ctx,
		targetCredentialTemplate.ID,
		targetCredentialTemplate.Type,
		profile,
	)

	if err != nil {
		return nil, err
	}

	txCredentialConfiguration := &issuecredential.TxCredentialConfiguration{
		ID:                    uuid.NewString(),
		CredentialTemplate:    targetCredentialTemplate,
		OIDCCredentialFormat:  metaCredentialConfiguration.Format,
		ClaimEndpoint:         credentialConfiguration.ClaimEndpoint,
		CredentialName:        credentialConfiguration.CredentialName,
		CredentialDescription: credentialConfiguration.CredentialDescription,
		CredentialExpiresAt: lo.ToPtr(
			s.GetCredentialsExpirationTime(credentialConfiguration.CredentialExpiresAt, targetCredentialTemplate)),
		CredentialConfigurationID: credentialConfigurationID,
		ClaimDataID:               "",
		PreAuthCodeExpiresAt:      nil,
		AuthorizationDetails:      nil,
	}

	if isPreAuthFlow {
		err = s.applyPreAuthFlowModifications(
			ctx,
			profile.DataConfig.ClaimDataTTL,
			credentialConfiguration,
			targetCredentialTemplate,
			txCredentialConfiguration,
		)
		if err != nil {
			return nil, err
		}
	}

	return txCredentialConfiguration, nil
}

func (s *Service) validateComposeCredential(credential map[string]interface{}) *oidc4cierr.Error {
	requiredFields := map[string]string{
		"issuer": "did:orb:anything",
	}

	if verifiable2.HasBaseContext(credential, verifiable2.V1ContextURI) {
		requiredFields["issuanceDate"] = "2021-01-01T00:00:00Z"
	}

	var missingFieldsAdded []string

	for key, value := range requiredFields {
		if _, ok := credential[key]; !ok {
			credential[key] = value
			missingFieldsAdded = append(missingFieldsAdded, key)
		}
	}

	if _, credCheckErr := verifiable2.ParseCredentialJSON(credential,
		verifiable2.WithJSONLDDocumentLoader(s.documentLoader),
		verifiable2.WithDisabledProofCheck(),
		verifiable2.WithStrictValidation(),
	); credCheckErr != nil {
		return oidc4cierr.NewBadRequestError(credCheckErr).
			WithErrorPrefix("parse credential").
			WithIncorrectValue("credential")
	}

	for _, key := range missingFieldsAdded {
		delete(credential, key)
	}

	return nil
}

func (s *Service) buildVirtualTemplate(req *InitiateIssuanceCredentialConfiguration) *profileapi.CredentialTemplate {
	result := &profileapi.CredentialTemplate{
		ID: fmt.Sprintf("virtual_%s", uuid.NewString()),
		Checks: profileapi.CredentialTemplateChecks{
			Strict: req.ComposeCredential.PerformStrictValidation,
		},
	}

	if req.ComposeCredential.Credential != nil {
		types := (*req.ComposeCredential.Credential)["type"]

		if v, ok := types.([]interface{}); ok && len(v) > 0 {
			targetType, targetOk := v[len(v)-1].(string)
			if targetOk {
				result.Type = targetType
			}
		}
	}

	return result
}

func (s *Service) applyPreAuthFlowModifications(
	ctx context.Context,
	profileClaimDataTTLSec int32,
	req InitiateIssuanceCredentialConfiguration,
	credentialTemplate *profileapi.CredentialTemplate,
	txCredentialConfiguration *issuecredential.TxCredentialConfiguration,
) *oidc4cierr.Error {
	var targetClaims map[string]interface{}
	if req.ClaimData != nil {
		if logger.IsEnabled(log.DEBUG) {
			claimKeys := make([]string, 0)
			for k := range req.ClaimData {
				claimKeys = append(claimKeys, k)
			}

			logger.Debugc(ctx, "issuer claim keys", logfields.WithClaimKeys(claimKeys))
		}

		if e := s.validateClaims(req.ClaimData, credentialTemplate); e != nil {
			return oidc4cierr.NewBadRequestError(e).WithErrorPrefix("validate claims")
		}

		targetClaims = req.ClaimData
		txCredentialConfiguration.ClaimDataType = issuecredential.ClaimDataTypeClaims
	} else if req.ComposeCredential != nil {
		targetClaims = lo.FromPtr(req.ComposeCredential.Credential)

		txCredentialConfiguration.ClaimDataType = issuecredential.ClaimDataTypeVC

		txCredentialConfiguration.CredentialComposeConfiguration = &issuecredential.CredentialComposeConfiguration{
			IDTemplate:         req.ComposeCredential.IDTemplate,
			OverrideIssuer:     req.ComposeCredential.OverrideIssuer,
			OverrideSubjectDID: req.ComposeCredential.OverrideSubjectDID,
		}
	}

	claimDataEncrypted, errEncrypt := s.EncryptClaims(ctx, targetClaims)
	if errEncrypt != nil {
		return oidc4cierr.NewBadRequestError(errEncrypt).
			WithComponent(resterr.DataProtectorComponent).
			WithErrorPrefix("encrypt claims")
	}

	claimDataID, claimDataErr := s.claimDataStore.Create(ctx, profileClaimDataTTLSec, claimDataEncrypted)
	if claimDataErr != nil {
		return oidc4cierr.NewBadRequestError(claimDataErr).
			WithOperation("create").
			WithComponent(resterr.ClaimDataStoreComponent).
			WithErrorPrefix("store claim data")
	}

	txCredentialConfiguration.ClaimDataID = claimDataID

	exp := time.Now().UTC().Add(time.Duration(s.preAuthCodeTTL) * time.Second)
	txCredentialConfiguration.PreAuthCodeExpiresAt = lo.ToPtr(exp)

	return nil
}

func setScopes(
	data *issuecredential.TransactionData, scopesSupported []string, requestScopes []string) *oidc4cierr.Error {
	if len(requestScopes) == 0 {
		data.Scope = scopesSupported
		return nil
	}

	for _, s := range requestScopes {
		if !lo.Contains(scopesSupported, s) {
			return oidc4cierr.NewBadRequestError(fmt.Errorf("unsupported scope %s", s)).
				WithIncorrectValue("scope")
		}
	}

	data.Scope = requestScopes

	return nil
}

func setGrantType(
	data *issuecredential.TransactionData, grantTypesSupported []string, requestGrantType string) *oidc4cierr.Error {
	if !lo.Contains(grantTypesSupported, requestGrantType) {
		return oidc4cierr.NewBadRequestError(
			fmt.Errorf("unsupported grant type %s", requestGrantType)).
			WithOperation("grant-type")
	}

	data.GrantType = requestGrantType

	return nil
}

func (s *Service) SelectProperOIDCFormat(
	format verifiable.Format,
	template *profileapi.CredentialTemplate,
) verifiable.OIDCFormat {
	if format == verifiable.Ldp {
		return verifiable.LdpVC
	}
	if format == verifiable.Cwt {
		return verifiable.CwtVcLD
	}

	if template.Checks.Strict {
		return verifiable.JwtVCJsonLD
	}

	return verifiable.JwtVCJson
}

func (s *Service) GetCredentialsExpirationTime(
	credentialExpiresAt *time.Time,
	template *profileapi.CredentialTemplate,
) time.Time {
	if credentialExpiresAt != nil {
		return *credentialExpiresAt
	}

	if template != nil && template.CredentialDefaultExpirationDuration != nil {
		return time.Now().UTC().Add(*template.CredentialDefaultExpirationDuration)
	}

	return time.Now().UTC().Add(365 * 24 * time.Hour)
}

func (s *Service) extendTransactionWithOIDCConfig(
	ctx context.Context,
	profile *profileapi.Issuer,
	data *issuecredential.TransactionData,
) *oidc4cierr.Error {
	if profile.OIDCConfig == nil || profile.OIDCConfig.IssuerWellKnownURL == "" {
		return nil
	}

	oidcConfig, err := s.wellKnownService.GetOIDCConfiguration(ctx, profile.OIDCConfig.IssuerWellKnownURL)
	if err != nil {
		return oidc4cierr.NewBadRequestError(err).
			WithOperation("GetOIDCConfig").
			WithErrorPrefix("get oidc configuration from well-known").
			WithComponent(resterr.WellKnownSvcComponent)
	}

	data.AuthorizationEndpoint = oidcConfig.AuthorizationEndpoint
	data.PushedAuthorizationRequestEndpoint = oidcConfig.PushedAuthorizationRequestEndpoint
	data.TokenEndpoint = oidcConfig.TokenEndpoint
	data.RedirectURI = fmt.Sprintf("%s/%s", s.issuerVCSPublicHost, "oidc/redirect")

	return nil
}

func generatePreAuthCode() string {
	return uuid.NewString() + fmt.Sprint(time.Now().UnixNano())
}

func findCredentialTemplateByID(
	credentialTemplates []*profileapi.CredentialTemplate,
	templateID string,
) (*profileapi.CredentialTemplate, *oidc4cierr.Error) {
	// profile should define at least one credential template
	if len(credentialTemplates) == 0 || credentialTemplates[0].ID == "" {
		return nil, oidc4cierr.NewBadRequestError(ErrCredentialTemplateNotConfigured)
	}

	// credential template ID is required if profile has more than one credential template defined
	if len(credentialTemplates) > 1 && templateID == "" {
		return nil, oidc4cierr.NewBadRequestError(ErrCredentialTemplateIDRequired)
	}

	for _, t := range credentialTemplates {
		if t.ID == templateID {
			return t, nil
		}
	}

	return nil, oidc4cierr.NewBadRequestError(ErrCredentialTemplateNotFound)
}

func findCredentialTemplate(
	requestedTemplateID string,
	profile *profileapi.Issuer,
) (*profileapi.CredentialTemplate, *oidc4cierr.Error) {
	if requestedTemplateID != "" {
		return findCredentialTemplateByID(profile.CredentialTemplates, requestedTemplateID)
	}

	if len(profile.CredentialTemplates) > 1 {
		return nil, oidc4cierr.NewBadRequestError(
			errors.New("credential template should be specified")).
			WithIncorrectValue("profile.CredentialTemplate")
	}

	return profile.CredentialTemplates[0], nil
}

func (s *Service) findCredentialConfigurationID(
	ctx context.Context,
	requestedTemplateID string,
	credentialType string,
	profile *profileapi.Issuer,
) (string, *profileapi.CredentialsConfigurationSupported, *oidc4cierr.Error) {
	for k, v := range profile.CredentialMetaData.CredentialsConfigurationSupported {
		if lo.Contains(v.CredentialDefinition.Type, credentialType) {
			return k, v, nil
		}
	}

	if profile.OIDCConfig.DynamicWellKnownSupported {
		id := uuid.NewString()

		vcFormat, err := common.MapToVCFormat(profile.VCConfig.Format)
		if err != nil {
			return "", nil, oidc4cierr.NewBadRequestError(err)
		}

		cfg := &profileapi.CredentialsConfigurationSupported{
			Format: vcFormat,
			CredentialDefinition: &profileapi.CredentialDefinition{
				Type: []string{credentialType},
			},
		}

		if err = s.wellKnownProvider.AddDynamicConfiguration(ctx, profile.ID, id, cfg); err != nil {
			return "", nil, oidc4cierr.NewBadRequestError(err)
		}

		return id, cfg, nil
	}

	return "", nil,
		oidc4cierr.NewBadRequestError(
			fmt.Errorf("credential configuration not found for requested template id %s", requestedTemplateID)).
			WithIncorrectValue("credential_template_id")
}

func (s *Service) prepareCredentialOffer(
	req *InitiateIssuanceRequest,
	tx *issuecredential.Transaction,
) *CredentialOfferResponse {
	issuerURL, _ := url.JoinPath(s.issuerVCSPublicHost, "oidc/idp", tx.ProfileID, tx.ProfileVersion)

	credentialConfigurationIDs := lo.Map(tx.CredentialConfiguration,
		func(item *issuecredential.TxCredentialConfiguration, _ int) string {
			return item.CredentialConfigurationID
		})

	resp := &CredentialOfferResponse{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: credentialConfigurationIDs,
		Grants:                     CredentialOfferGrant{},
	}

	if tx.IsPreAuthFlow {
		preAuthorizationGrant := &PreAuthorizationGrant{
			PreAuthorizedCode: tx.PreAuthCode,
		}

		if req.UserPinRequired {
			preAuthorizationGrant.TxCode = &TxCode{
				InputMode:   "numeric",
				Length:      TxCodeLength,
				Description: "Pin",
			}
		}

		resp.Grants.PreAuthorizationGrant = preAuthorizationGrant
	} else {
		resp.Grants.AuthorizationCode = &AuthorizationCodeGrant{
			IssuerState: req.OpState,
		}
	}

	return resp
}

// JWTCredentialOfferClaims is JWT Claims extension by CredentialOfferResponse (with custom "credential_offer" claim).
type JWTCredentialOfferClaims struct {
	*jwt.Claims

	CredentialOffer *CredentialOfferResponse `json:"credential_offer,omitempty"`
}

func (s *Service) getJWTCredentialOfferClaims(
	profileSigningDID string,
	credentialOffer *CredentialOfferResponse,
) *JWTCredentialOfferClaims {
	return &JWTCredentialOfferClaims{
		Claims: &jwt.Claims{
			Issuer:   profileSigningDID,
			Subject:  profileSigningDID,
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
		CredentialOffer: credentialOffer,
	}
}

// storeCredentialOffer stores signedCredentialOfferJWT or CredentialOfferResponse object
// to underlying credentialOfferReferenceStore.
//
// Returns:
//
//	remoteOfferURL
//	error
//
// returned remoteOfferURL might be empty in case credentialOfferReferenceStore is not initialized.
func (s *Service) storeCredentialOffer( //nolint:nonamedreturns
	ctx context.Context,
	credentialOffer *CredentialOfferResponse,
	signedCredentialOfferJWT string,
) (remoteOfferURL string, err error) {
	if s.credentialOfferReferenceStore == nil {
		return "", nil
	}

	if signedCredentialOfferJWT != "" {
		return s.credentialOfferReferenceStore.CreateJWT(ctx, signedCredentialOfferJWT)
	}

	return s.credentialOfferReferenceStore.Create(ctx, credentialOffer)
}

func (s *Service) getSignedCredentialOfferJWT(
	profile *profileapi.Issuer,
	credentialOffer *CredentialOfferResponse,
) (string, *oidc4cierr.Error) {
	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return "", oidc4cierr.NewBadRequestError(err).WithErrorPrefix("get kms")
	}

	signerData := &vc.Signer{
		KeyType:       profile.VCConfig.KeyType,
		KMSKeyID:      profile.SigningDID.KMSKeyID,
		KMS:           kms,
		SignatureType: profile.VCConfig.SigningAlgorithm,
		Creator:       profile.SigningDID.Creator,
	}

	credentialOfferClaims := s.getJWTCredentialOfferClaims(profile.SigningDID.DID, credentialOffer)

	signedCredentialOffer, err := s.cryptoJWTSigner.NewJWTSigned(credentialOfferClaims, signerData)
	if err != nil {
		return "", oidc4cierr.NewBadRequestError(err).
			WithErrorPrefix("sign credential offer").
			WithComponent(resterr.CryptoJWTSignerComponent).
			WithOperation("sign")
	}

	return signedCredentialOffer, nil
}

func (s *Service) buildInitiateIssuanceURL(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	tx *issuecredential.Transaction,
	profile *profileapi.Issuer,
) (string, InitiateIssuanceResponseContentType, *oidc4cierr.Error) {
	credentialOffer := s.prepareCredentialOffer(req, tx)

	var (
		signedCredentialOfferJWT string
		remoteOfferURL           string
		oidcError                *oidc4cierr.Error
		err                      error
	)

	if profile.OIDCConfig.SignedCredentialOfferSupported {
		signedCredentialOfferJWT, oidcError = s.getSignedCredentialOfferJWT(profile, credentialOffer)
		if oidcError != nil {
			return "", "", oidcError
		}
	}

	remoteOfferURL, err = s.storeCredentialOffer(ctx, credentialOffer, signedCredentialOfferJWT)
	if err != nil {
		return "", "", oidc4cierr.NewBadRequestError(err).
			WithComponent(resterr.CredentialOfferReferenceStoreComponent).
			WithOperation("store")
	}

	initiateIssuanceQueryParams, getParamsError := s.getInitiateIssuanceQueryParams(
		remoteOfferURL, signedCredentialOfferJWT, credentialOffer)
	if getParamsError != nil {
		return "", "", oidc4cierr.NewBadRequestError(err).
			WithComponent(resterr.IssuerSvcComponent).
			WithOperation("get-query-params")
	}

	ct := ContentTypeApplicationJSON
	if signedCredentialOfferJWT != "" {
		ct = ContentTypeApplicationJWT
	}

	initiateIssuanceURL := s.getInitiateIssuanceURL(ctx, req)

	return initiateIssuanceURL + "?" + initiateIssuanceQueryParams.Encode(), ct, nil
}

func (s *Service) getInitiateIssuanceQueryParams(
	remoteOfferURL, signedCredentialOfferJWT string,
	credentialOffer *CredentialOfferResponse,
) (url.Values, error) {
	q := url.Values{}
	if remoteOfferURL != "" {
		q.Set("credential_offer_uri", remoteOfferURL)

		return q, nil
	}

	if signedCredentialOfferJWT != "" {
		q.Set("credential_offer", signedCredentialOfferJWT)

		return q, nil
	}

	b, err := json.Marshal(credentialOffer)
	if err != nil {
		return nil, err
	}

	q.Set("credential_offer", string(b))

	return q, nil
}

func (s *Service) getInitiateIssuanceURL(ctx context.Context, req *InitiateIssuanceRequest) string {
	var initiateIssuanceURL string

	if req.ClientInitiateIssuanceURL != "" {
		initiateIssuanceURL = req.ClientInitiateIssuanceURL
	} else if req.ClientWellKnownURL != "" {
		c, err := s.wellKnownService.GetOIDCConfiguration(ctx, req.ClientWellKnownURL)
		if err != nil {
			logger.Errorc(ctx, "Failed to get OIDC configuration from well-known",
				log.WithError(err), log.WithURL(req.ClientWellKnownURL))
		} else {
			initiateIssuanceURL = c.InitiateIssuanceEndpoint
		}
	}

	if initiateIssuanceURL == "" {
		initiateIssuanceURL = "openid-credential-offer://"
	}

	return initiateIssuanceURL
}

func (s *Service) validateClaims(
	claims map[string]interface{},
	credentialTemplate *profileapi.CredentialTemplate,
) error {
	if credentialTemplate == nil || credentialTemplate.JSONSchemaID == "" {
		return nil
	}

	logger.Debug("Validating claims against JSON schema",
		logfields.WithCredentialTemplateID(credentialTemplate.ID),
		logfields.WithJSONSchemaID(credentialTemplate.JSONSchemaID),
	)

	return s.schemaValidator.Validate(claims, credentialTemplate.JSONSchemaID,
		[]byte(credentialTemplate.JSONSchema))
}
