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

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
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
) (*InitiateIssuanceResponse, error) {
	if req.OpState == "" {
		req.OpState = uuid.NewString()
	}

	if !profile.Active {
		return nil, resterr.ErrProfileInactive
	}

	if profile.VCConfig == nil {
		return nil, resterr.ErrVCOptionsNotConfigured
	}

	if req.GrantType != GrantTypeAuthorizationCode && req.GrantType != GrantTypePreAuthorizedCode {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "grant_type",
			fmt.Errorf("unexpected grant_type supplied %s", req.GrantType))
	}

	isPreAuthFlow := req.GrantType == GrantTypePreAuthorizedCode
	if !isPreAuthFlow && profile.OIDCConfig == nil {
		return nil, resterr.ErrAuthorizedCodeFlowNotSupported
	}

	issuedCredentialConfiguration := make(map[string]*TxCredentialConfiguration)

	// If req.CredentialTemplateID supplied - create TxCredentialConfiguration based on it.
	if req.CredentialTemplateID != "" { //nolint:nestif
		credentialConfigurationID, txCredentialConf, err := s.newTxConfUsingTemplateID(
			ctx, req, isPreAuthFlow, profile)
		if err != nil {
			return nil, err
		}

		issuedCredentialConfiguration[credentialConfigurationID] = txCredentialConf
	}

	// Multiple credential issuance - use req.CredentialConfiguration to create TxCredentialConfiguration.
	for _, credentialConfiguration := range req.CredentialConfiguration {
		credentialConfigurationID, txCredentialConf, err := s.newTxConfUsingCredentialConf(
			ctx, credentialConfiguration, isPreAuthFlow, profile)
		if err != nil {
			return nil, err
		}

		issuedCredentialConfiguration[credentialConfigurationID] = txCredentialConf
	}

	txState := TransactionStateIssuanceInitiated
	if req.WalletInitiatedIssuance {
		txState = TransactionStateAwaitingIssuerOIDCAuthorization
	}

	opState := req.OpState

	var preAuthCode string
	if isPreAuthFlow {
		preAuthCode = generatePreAuthCode()
		opState = preAuthCode // set opState as it will be empty for pre-auth
	}

	txData := &TransactionData{
		ProfileID:               profile.ID,
		ProfileVersion:          profile.Version,
		OrgID:                   profile.OrganizationID,
		ResponseType:            req.ResponseType,
		State:                   txState,
		WebHookURL:              profile.WebHook,
		DID:                     profile.SigningDID.DID,
		WalletInitiatedIssuance: req.WalletInitiatedIssuance,
		IsPreAuthFlow:           isPreAuthFlow,
		PreAuthCode:             preAuthCode,
		OpState:                 opState,
		CredentialConfiguration: issuedCredentialConfiguration,
	}

	var err error
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

	tx, err := s.store.Create(ctx, txData)
	if err != nil {
		return nil, resterr.NewSystemError(resterr.TransactionStoreComponent, "create",
			fmt.Errorf("store tx: %w", err))
	}

	finalURL, contentType, err := s.buildInitiateIssuanceURL(ctx, req, tx, profile)
	if err != nil {
		return nil, err
	}

	if errSendEvent := s.sendInitiateIssuanceEvent(ctx, tx, finalURL); errSendEvent != nil {
		return nil, errSendEvent
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
	claimEndpoint string,
	claimData map[string]interface{},
) error {
	if isPreAuthFlow {
		if len(claimData) == 0 {
			return resterr.NewValidationError(resterr.InvalidValue, "claim_data",
				errors.New("claim_data param is not supplied"))
		}
	} else {
		if len(claimEndpoint) == 0 {
			return resterr.NewValidationError(resterr.InvalidValue, "claim_data",
				errors.New("claim_endpoint param is not supplied"))
		}
	}

	return nil
}

func (s *Service) newTxConfUsingTemplateID(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	isPreAuthFlow bool,
	profile *profileapi.Issuer,
) (string, *TxCredentialConfiguration, error) {
	err := s.validateFlowSpecificRequestParams(isPreAuthFlow, req.ClaimEndpoint, req.ClaimData)
	if err != nil {
		return "", nil, err
	}

	credentialTemplate, err := findCredentialTemplate(req.CredentialTemplateID, profile)
	if err != nil {
		return "", nil, err
	}

	credentialConfigurationID, credentialConfiguration, err := findCredentialConfigurationID(
		req.CredentialTemplateID, credentialTemplate.Type, profile)
	if err != nil {
		return "", nil, err
	}

	txCredentialConfiguration := &TxCredentialConfiguration{
		CredentialTemplate:    credentialTemplate,
		OIDCCredentialFormat:  credentialConfiguration.Format,
		ClaimEndpoint:         req.ClaimEndpoint,
		CredentialName:        req.CredentialName,
		CredentialDescription: req.CredentialDescription,
		CredentialExpiresAt:   lo.ToPtr(s.GetCredentialsExpirationTime(req.CredentialExpiresAt, credentialTemplate)),
		ClaimDataID:           "",
		PreAuthCodeExpiresAt:  nil,
		AuthorizationDetails:  nil,
	}

	if isPreAuthFlow {
		err = s.applyPreAuthFlowModifications(ctx, InitiateIssuanceCredentialConfiguration{
			ClaimData: req.ClaimData,
		}, credentialTemplate, txCredentialConfiguration)
		if err != nil {
			return "", nil, err
		}
	}

	return credentialConfigurationID, txCredentialConfiguration, nil
}

func (s *Service) newTxConfUsingCredentialConf(
	ctx context.Context,
	credentialConfiguration InitiateIssuanceCredentialConfiguration,
	isPreAuthFlow bool,
	profile *profileapi.Issuer,
) (string, *TxCredentialConfiguration, error) {
	err := s.validateFlowSpecificRequestParams(
		isPreAuthFlow, credentialConfiguration.ClaimEndpoint, credentialConfiguration.ClaimData)
	if err != nil {
		return "", nil, err
	}

	credentialTemplate, err := findCredentialTemplate(credentialConfiguration.CredentialTemplateID, profile)
	if err != nil {
		return "", nil, err
	}

	credentialConfigurationID, _, err := findCredentialConfigurationID(
		credentialTemplate.ID, credentialTemplate.Type, profile)
	if err != nil {
		return "", nil, err
	}

	profileMeta := profile.CredentialMetaData

	metaCredentialConfiguration := profileMeta.CredentialsConfigurationSupported[credentialConfigurationID]

	txCredentialConfiguration := &TxCredentialConfiguration{
		CredentialTemplate:    credentialTemplate,
		OIDCCredentialFormat:  metaCredentialConfiguration.Format,
		ClaimEndpoint:         credentialConfiguration.ClaimEndpoint,
		CredentialName:        credentialConfiguration.CredentialName,
		CredentialDescription: credentialConfiguration.CredentialDescription,
		CredentialExpiresAt: lo.ToPtr(
			s.GetCredentialsExpirationTime(credentialConfiguration.CredentialExpiresAt, credentialTemplate)),
		ClaimDataID:          "",
		PreAuthCodeExpiresAt: nil,
		AuthorizationDetails: nil,
	}

	if isPreAuthFlow {
		err = s.applyPreAuthFlowModifications(
			ctx,
			credentialConfiguration,
			credentialTemplate,
			txCredentialConfiguration,
		)
		if err != nil {
			return "", nil, err
		}
	}

	return credentialConfigurationID, txCredentialConfiguration, nil
}

func (s *Service) applyPreAuthFlowModifications(
	ctx context.Context,
	req InitiateIssuanceCredentialConfiguration,
	credentialTemplate *profileapi.CredentialTemplate,
	txCredentialConfiguration *TxCredentialConfiguration,
) error {
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
			return resterr.NewCustomError(resterr.ClaimsValidationErr,
				fmt.Errorf("validate claims: %w", e))
		}

		targetClaims = req.ClaimData
		txCredentialConfiguration.ClaimDataType = ClaimDataTypeClaims

	} else if req.ComposeCredential != nil {
		targetClaims = lo.FromPtr(req.ComposeCredential.Credential)

		txCredentialConfiguration.ClaimDataType = ClaimDataTypeVC
		txCredentialConfiguration.CredentialComposeConfiguration = &CredentialComposeConfiguration{
			IdTemplate: req.ComposeCredential.IdTemplate,
		}
	}

	claimDataEncrypted, errEncrypt := s.EncryptClaims(ctx, targetClaims)
	if errEncrypt != nil {
		return errEncrypt
	}

	claimDataID, claimDataErr := s.claimDataStore.Create(ctx, claimDataEncrypted)
	if claimDataErr != nil {
		return resterr.NewSystemError(resterr.ClaimDataStoreComponent, "create",
			fmt.Errorf("store claim data: %w", claimDataErr))
	}

	txCredentialConfiguration.ClaimDataID = claimDataID

	exp := time.Now().UTC().Add(time.Duration(s.preAuthCodeTTL) * time.Second)
	txCredentialConfiguration.PreAuthCodeExpiresAt = lo.ToPtr(exp)

	return nil
}

func setScopes(data *TransactionData, scopesSupported []string, requestScopes []string) error {
	if len(requestScopes) == 0 {
		data.Scope = scopesSupported
		return nil
	}

	for _, s := range requestScopes {
		if !lo.Contains(scopesSupported, s) {
			return resterr.NewValidationError(resterr.InvalidValue, "scope",
				fmt.Errorf("unsupported scope %s", s))
		}
	}

	data.Scope = requestScopes

	return nil
}

func setGrantType(data *TransactionData, grantTypesSupported []string, requestGrantType string) error {
	if !lo.Contains(grantTypesSupported, requestGrantType) {
		return resterr.NewValidationError(resterr.InvalidValue, "grant-type",
			fmt.Errorf("unsupported grant type %s", requestGrantType))
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
	data *TransactionData,
) error {
	if profile.OIDCConfig == nil || profile.OIDCConfig.IssuerWellKnownURL == "" {
		return nil
	}

	oidcConfig, err := s.wellKnownService.GetOIDCConfiguration(ctx, profile.OIDCConfig.IssuerWellKnownURL)
	if err != nil {
		return resterr.NewSystemError(resterr.WellKnownSvcComponent, "GetOIDCConfig",
			fmt.Errorf("get oidc configuration from well-known: %w", err))
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
) (*profileapi.CredentialTemplate, error) {
	// profile should define at least one credential template
	if len(credentialTemplates) == 0 || credentialTemplates[0].ID == "" {
		return nil, resterr.ErrCredentialTemplateNotConfigured
	}

	// credential template ID is required if profile has more than one credential template defined
	if len(credentialTemplates) > 1 && templateID == "" {
		return nil, resterr.ErrCredentialTemplateIDRequired
	}

	for _, t := range credentialTemplates {
		if t.ID == templateID {
			return t, nil
		}
	}

	return nil, resterr.ErrCredentialTemplateNotFound
}

func findCredentialTemplate(
	requestedTemplateID string,
	profile *profileapi.Issuer,
) (*profileapi.CredentialTemplate, error) {
	if requestedTemplateID != "" {
		return findCredentialTemplateByID(profile.CredentialTemplates, requestedTemplateID)
	}

	if len(profile.CredentialTemplates) > 1 {
		return nil, resterr.NewValidationError(resterr.ConditionNotMet, "profile.CredentialTemplate",
			errors.New("credential template should be specified"))
	}

	return profile.CredentialTemplates[0], nil
}

func findCredentialConfigurationID(
	requestedTemplateID string,
	credentialType string,
	profile *profileapi.Issuer,
) (string, *profileapi.CredentialsConfigurationSupported, error) {
	for k, v := range profile.CredentialMetaData.CredentialsConfigurationSupported {
		if lo.Contains(v.CredentialDefinition.Type, credentialType) {
			return k, v, nil
		}
	}

	return "", nil, resterr.NewValidationError(resterr.InvalidValue, "credential_template_id",
		fmt.Errorf("credential configuration not found for requested template id %s", requestedTemplateID))
}

func (s *Service) prepareCredentialOffer(
	req *InitiateIssuanceRequest,
	tx *Transaction,
) *CredentialOfferResponse {
	issuerURL, _ := url.JoinPath(s.issuerVCSPublicHost, "oidc/idp", tx.ProfileID, tx.ProfileVersion)

	resp := &CredentialOfferResponse{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: lo.Keys(tx.CredentialConfiguration),
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
) (string, error) {
	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return "", fmt.Errorf("get kms: %w", err)
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
		return "", resterr.NewSystemError(resterr.CryptoJWTSignerComponent, "sign",
			fmt.Errorf("sign credential offer: %w", err))
	}

	return signedCredentialOffer, nil
}

func (s *Service) buildInitiateIssuanceURL(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	tx *Transaction,
	profile *profileapi.Issuer,
) (string, InitiateIssuanceResponseContentType, error) {
	credentialOffer := s.prepareCredentialOffer(req, tx)

	var (
		signedCredentialOfferJWT string
		remoteOfferURL           string
		err                      error
	)

	if profile.OIDCConfig.SignedCredentialOfferSupported {
		signedCredentialOfferJWT, err = s.getSignedCredentialOfferJWT(profile, credentialOffer)
		if err != nil {
			return "", "", err
		}
	}

	remoteOfferURL, err = s.storeCredentialOffer(ctx, credentialOffer, signedCredentialOfferJWT)
	if err != nil {
		return "", "", resterr.NewSystemError(resterr.CredentialOfferReferenceStoreComponent, "store", err)
	}

	initiateIssuanceQueryParams, err := s.getInitiateIssuanceQueryParams(
		remoteOfferURL, signedCredentialOfferJWT, credentialOffer)
	if err != nil {
		return "", "", resterr.NewSystemError(resterr.IssuerSvcComponent, "get-query-params", err)
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
