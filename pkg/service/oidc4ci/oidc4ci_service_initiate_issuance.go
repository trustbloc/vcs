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

	isPreAuthorizeFlow := len(req.ClaimData) > 0

	if !isPreAuthorizeFlow && profile.OIDCConfig == nil {
		return nil, resterr.ErrAuthorizedCodeFlowNotSupported
	}

	template, err := s.findCredentialTemplate(req.CredentialTemplateID, profile)
	if err != nil {
		return nil, err
	}

	txData := &TransactionData{
		ProfileID:               profile.ID,
		ProfileVersion:          profile.Version,
		OrgID:                   profile.OrganizationID,
		CredentialTemplate:      template,
		CredentialFormat:        profile.VCConfig.Format,
		OIDCCredentialFormat:    s.SelectProperOIDCFormat(profile.VCConfig.Format, template),
		ClaimEndpoint:           req.ClaimEndpoint,
		ResponseType:            req.ResponseType,
		OpState:                 req.OpState,
		State:                   TransactionStateIssuanceInitiated,
		WebHookURL:              profile.WebHook,
		DID:                     profile.SigningDID.DID,
		CredentialExpiresAt:     lo.ToPtr(s.GetCredentialsExpirationTime(req, template)),
		CredentialName:          req.CredentialName,
		CredentialDescription:   req.CredentialDescription,
		WalletInitiatedIssuance: req.WalletInitiatedIssuance,
	}

	if req.WalletInitiatedIssuance {
		txData.State = TransactionStateAwaitingIssuerOIDCAuthorization
	}

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

	if isPreAuthorizeFlow {
		if logger.IsEnabled(log.DEBUG) {
			claimKeys := make([]string, 0)
			for k := range req.ClaimData {
				claimKeys = append(claimKeys, k)
			}

			logger.Debugc(ctx, "issuer claim keys", logfields.WithClaimKeys(claimKeys))
		}

		if e := s.validateClaims(req.ClaimData, template); e != nil {
			return nil, resterr.NewCustomError(resterr.ClaimsValidationErr,
				fmt.Errorf("validate claims: %w", e))
		}

		claimData, errEncrypt := s.EncryptClaims(ctx, req.ClaimData)
		if errEncrypt != nil {
			return nil, errEncrypt
		}

		claimDataID, claimDataErr := s.claimDataStore.Create(ctx, claimData)
		if claimDataErr != nil {
			return nil, resterr.NewSystemError(resterr.ClaimDataStoreComponent, "create",
				fmt.Errorf("store claim data: %w", claimDataErr))
		}

		txData.ClaimDataID = claimDataID

		txData.IsPreAuthFlow = true
		txData.PreAuthCode = generatePreAuthCode()
		txData.PreAuthCodeExpiresAt = lo.ToPtr(time.Now().UTC().Add(time.Duration(s.preAuthCodeTTL) * time.Second))
		txData.OpState = txData.PreAuthCode // set opState as it will be empty for pre-auth
	}

	if req.UserPinRequired {
		txData.UserPin = s.pinGenerator.Generate(uuid.NewString())
	}

	tx, err := s.store.Create(ctx, txData)
	if err != nil {
		return nil, resterr.NewSystemError(resterr.TransactionStoreComponent, "create",
			fmt.Errorf("store tx: %w", err))
	}

	finalURL, contentType, err := s.buildInitiateIssuanceURL(ctx, req, template, tx, profile)
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
	if requestGrantType == "" {
		data.GrantType = defaultGrantType
		return nil
	}

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
	req *InitiateIssuanceRequest,
	template *profileapi.CredentialTemplate,
) time.Time {
	if req != nil && req.CredentialExpiresAt != nil {
		return *req.CredentialExpiresAt
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

func findCredentialTemplate(
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

func (s *Service) findCredentialTemplate(
	requestedTemplateID string,
	profile *profileapi.Issuer,
) (*profileapi.CredentialTemplate, error) {
	if requestedTemplateID != "" {
		return findCredentialTemplate(profile.CredentialTemplates, requestedTemplateID)
	}

	if len(profile.CredentialTemplates) > 1 {
		return nil, resterr.NewValidationError(resterr.ConditionNotMet, "profile.CredentialTemplate",
			errors.New("credential template should be specified"))
	}

	return profile.CredentialTemplates[0], nil
}

func (s *Service) prepareCredentialOffer(
	req *InitiateIssuanceRequest,
	template *profileapi.CredentialTemplate,
	tx *Transaction,
) *CredentialOfferResponse {
	issuerURL, _ := url.JoinPath(s.issuerVCSPublicHost, "oidc/idp", tx.ProfileID, tx.ProfileVersion)

	resp := &CredentialOfferResponse{
		CredentialIssuer: issuerURL,
		Credentials: []CredentialOffer{
			{
				Format: tx.OIDCCredentialFormat,
				Types: []string{
					"VerifiableCredential",
					template.Type,
				},
			},
		},
		Grants: CredentialOfferGrant{},
	}

	if tx.IsPreAuthFlow {
		resp.Grants.PreAuthorizationGrant = &PreAuthorizationGrant{
			PreAuthorizedCode: tx.PreAuthCode,
			UserPinRequired:   req.UserPinRequired,
		}
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
	template *profileapi.CredentialTemplate,
	tx *Transaction,
	profile *profileapi.Issuer,
) (string, InitiateIssuanceResponseContentType, error) {
	credentialOffer := s.prepareCredentialOffer(req, template, tx)

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
