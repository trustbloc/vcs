/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4ci_service_mocks_test.go -self_package mocks -package oidc4ci_test -source=oidc4ci_service.go -mock_names transactionStore=MockTransactionStore,wellKnownService=MockWellKnownService,eventService=MockEventService,pinGenerator=MockPinGenerator,credentialOfferReferenceStore=MockCredentialOfferReferenceStore,claimDataStore=MockClaimDataStore,profileService=MockProfileService,dataProtector=MockDataProtector,kmsRegistry=MockKMSRegistry,cryptoJWTSigner=MockCryptoJWTSigner,jsonSchemaValidator=MockJSONSchemaValidator,trustRegistry=MockTrustRegistry,ackStore=MockAckStore,ackService=MockAckService,composer=MockComposer

package oidc4ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/samber/lo"
	util "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/trustregistry"
)

const (
	defaultGrantType        = "authorization_code"
	defaultResponseType     = "token"
	defaultCtx              = "https://www.w3.org/2018/credentials/v1"
	attestJWTClientAuthType = "attest_jwt_client_auth"
)

var _ ServiceInterface = (*Service)(nil)

var logger = log.New("oidc4ci")

type pinGenerator interface {
	Generate(challenge string) string
	Validate(challenge string, userInput string) bool
}

type transactionStore interface {
	Create(
		ctx context.Context,
		data *TransactionData,
		params ...func(insertOptions *InsertOptions),
	) (*Transaction, error)

	Get(
		ctx context.Context,
		txID TxID,
	) (*Transaction, error)

	FindByOpState(
		ctx context.Context,
		opState string,
	) (*Transaction, error)

	Update(
		ctx context.Context,
		tx *Transaction,
	) error
}

type claimDataStore interface {
	Create(ctx context.Context, data *ClaimData) (string, error)
	GetAndDelete(ctx context.Context, id string) (*ClaimData, error)
}

type wellKnownService interface {
	GetOIDCConfiguration(
		ctx context.Context,
		url string,
	) (*IssuerIDPOIDCConfiguration, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error)
}

type eventService interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type credentialOfferReferenceStore interface {
	Create(
		ctx context.Context,
		credentialOffer *CredentialOfferResponse,
	) (string, error)
	CreateJWT(
		ctx context.Context,
		credentialOfferJWT string,
	) (string, error)
}

type dataProtector interface {
	Encrypt(ctx context.Context, msg []byte) (*dataprotect.EncryptedData, error)
	Decrypt(ctx context.Context, encryptedData *dataprotect.EncryptedData) ([]byte, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type cryptoJWTSigner interface {
	NewJWTSigned(claims interface{}, signerData *vc.Signer) (string, error)
}

type jsonSchemaValidator interface {
	Validate(data interface{}, schemaID string, schema []byte) error
}

type trustRegistry interface {
	trustregistry.ValidateIssuance
}

type ackStore interface {
	Create(ctx context.Context, data *Ack) (string, error)
	Get(ctx context.Context, id string) (*Ack, error)
	Delete(ctx context.Context, id string) error
}

type ackService interface {
	Ack(
		ctx context.Context,
		req AckRemote,
	) error
	CreateAck(
		ctx context.Context,
		ack *Ack,
	) (*string, error)
}

type composer interface {
	Compose(
		ctx context.Context,
		credential *verifiable.Credential,
		tx *Transaction,
		txCredentialConfiguration *TxCredentialConfiguration,
		req *PrepareCredentialRequest,
	) (*verifiable.Credential, error)
}

// Config holds configuration options and dependencies for Service.
type Config struct {
	TransactionStore              transactionStore
	ClaimDataStore                claimDataStore
	WellKnownService              wellKnownService
	ProfileService                profileService
	IssuerVCSPublicHost           string
	HTTPClient                    *http.Client
	EventService                  eventService
	PinGenerator                  pinGenerator
	EventTopic                    string
	PreAuthCodeTTL                int32
	CredentialOfferReferenceStore credentialOfferReferenceStore // optional
	DataProtector                 dataProtector
	KMSRegistry                   kmsRegistry
	CryptoJWTSigner               cryptoJWTSigner
	JSONSchemaValidator           jsonSchemaValidator
	TrustRegistry                 trustRegistry
	AckService                    ackService
	Composer                      composer
}

// Service implements VCS credential interaction API for OIDC credential issuance.
type Service struct {
	store                         transactionStore
	claimDataStore                claimDataStore
	wellKnownService              wellKnownService
	profileService                profileService
	issuerVCSPublicHost           string
	httpClient                    *http.Client
	eventSvc                      eventService
	eventTopic                    string
	pinGenerator                  pinGenerator
	preAuthCodeTTL                int32
	credentialOfferReferenceStore credentialOfferReferenceStore // optional
	dataProtector                 dataProtector
	kmsRegistry                   kmsRegistry
	cryptoJWTSigner               cryptoJWTSigner
	schemaValidator               jsonSchemaValidator
	trustRegistry                 trustRegistry
	ackService                    ackService
	composer                      composer
}

// NewService returns a new Service instance.
func NewService(config *Config) (*Service, error) {
	return &Service{
		store:                         config.TransactionStore,
		claimDataStore:                config.ClaimDataStore,
		wellKnownService:              config.WellKnownService,
		profileService:                config.ProfileService,
		issuerVCSPublicHost:           config.IssuerVCSPublicHost,
		httpClient:                    config.HTTPClient,
		eventSvc:                      config.EventService,
		eventTopic:                    config.EventTopic,
		pinGenerator:                  config.PinGenerator,
		preAuthCodeTTL:                config.PreAuthCodeTTL,
		credentialOfferReferenceStore: config.CredentialOfferReferenceStore,
		dataProtector:                 config.DataProtector,
		kmsRegistry:                   config.KMSRegistry,
		cryptoJWTSigner:               config.CryptoJWTSigner,
		schemaValidator:               config.JSONSchemaValidator,
		trustRegistry:                 config.TrustRegistry,
		ackService:                    config.AckService,
		composer:                      config.Composer,
	}, nil
}

func (s *Service) PushAuthorizationDetails(
	ctx context.Context,
	opState string,
	ad []*AuthorizationDetails,
) error {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return fmt.Errorf("find tx by op state: %w", err)
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return resterr.NewCustomError(resterr.ProfileNotFound, err)
		}

		return resterr.NewSystemError(resterr.IssuerProfileSvcComponent, "GetProfile", err)
	}

	var requestedCredentialConfigurationIDs map[string]struct{}
	if requestedCredentialConfigurationIDs, err = s.enrichTxCredentialConfigurationsWithAuthorizationDetails(
		profile,
		tx.CredentialConfiguration,
		ad,
	); err != nil {
		return err
	}

	// Delete unused keys from tx.CredentialConfiguration
	for credentialConfigurationID := range tx.CredentialConfiguration {
		if _, ok := requestedCredentialConfigurationIDs[credentialConfigurationID]; !ok {
			delete(tx.CredentialConfiguration, credentialConfigurationID)
		}
	}

	if err = s.store.Update(ctx, tx); err != nil {
		return resterr.NewSystemError(resterr.TransactionStoreComponent, "Update", err)
	}

	return nil
}

// checkScopes checks request scope against Transaction.
//
// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.2
//
//nolint:lll,gocognit
func (s *Service) checkScopes(
	profile *profileapi.Issuer,
	reqScopes []string,
	txScope []string,
	txCredentialConfigurations map[string]*TxCredentialConfiguration,
	requestedCredentialConfigurationIDsViaAuthDetails map[string]struct{},
) ([]string, error) {
	var credentialsConfigurationSupported map[string]*profileapi.CredentialsConfigurationSupported
	if meta := profile.CredentialMetaData; meta != nil {
		credentialsConfigurationSupported = meta.CredentialsConfigurationSupported
	}

	var validScopes []string

	// Check each request scope.
	for _, reqScope := range reqScopes {
		if !lo.Contains(txScope, reqScope) {
			return nil, resterr.ErrInvalidScope
		}

		if !lo.Contains(profile.OIDCConfig.ScopesSupported, reqScope) {
			// Credential Issuers MUST ignore unknown scope values in a request.
			continue
		}

		validScopes = append(validScopes, reqScope)

		// Find metaCredentialConfiguration based on reqScope.
		// Check if some metaCredentialConfiguration was requsted using the scope.
		for credentialConfigurationID, metaCredentialConfiguration := range credentialsConfigurationSupported {
			if !strings.EqualFold(reqScope, metaCredentialConfiguration.Scope) {
				continue
			}

			// On this moment credentialConfigurationID is defined.

			// If a scope value related to Credential issuance and the authorization_details request parameter
			// containing objects of type openid_credential are both present in a single request, the Credential Issuer MUST
			// interpret these individually. However, if both request the same Credential type, then the Credential Issuer MUST
			// follow the request as given by the authorization_details object.
			if _, ok := requestedCredentialConfigurationIDsViaAuthDetails[credentialConfigurationID]; ok {
				continue
			}

			// Get txCredentialConfig.
			txCredentialConfig, ok := txCredentialConfigurations[credentialConfigurationID]
			if !ok {
				return nil, resterr.ErrInvalidScope
			}

			// Check format.
			if metaCredentialConfiguration.Format != txCredentialConfig.OIDCCredentialFormat {
				return nil, resterr.ErrCredentialFormatNotSupported
			}

			// Check credential type.
			var targetType string
			if cd := metaCredentialConfiguration.CredentialDefinition; cd != nil {
				targetType = cd.Type[len(cd.Type)-1]
			}

			if !strings.EqualFold(targetType, txCredentialConfig.CredentialTemplate.Type) {
				return nil, resterr.ErrCredentialTypeNotSupported
			}

			requestedCredentialConfigurationIDsViaAuthDetails[credentialConfigurationID] = struct{}{}
			break
		}
	}

	return lo.Uniq(validScopes), nil
}

func (s *Service) PrepareClaimDataAuthorizationRequest(
	ctx context.Context,
	req *PrepareClaimDataAuthorizationRequest,
) (*PrepareClaimDataAuthorizationResponse, error) {
	tx, err := s.store.FindByOpState(ctx, req.OpState)

	if err != nil && errors.Is(err, resterr.ErrDataNotFound) {
		// process wallet initiated flow
		walletFlowResp, walletFlowErr := s.prepareClaimDataAuthorizationRequestWalletInitiated(
			ctx,
			req.Scope,
			ExtractIssuerURL(req.OpState),
		)
		if walletFlowErr != nil && errors.Is(walletFlowErr, resterr.ErrInvalidIssuerURL) { // not wallet-initiated flow
			return nil, err
		}

		return walletFlowResp, walletFlowErr
	}

	if err != nil {
		return nil, err
	}

	newState := TransactionStateAwaitingIssuerOIDCAuthorization
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return nil, err
	}

	tx.State = newState

	if req.ResponseType != tx.ResponseType {
		return nil, resterr.ErrResponseTypeMismatch
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, resterr.NewCustomError(resterr.ProfileNotFound,
				fmt.Errorf("update tx auth details: get profile: %w", err))
		}

		return nil, resterr.NewSystemError(resterr.IssuerProfileSvcComponent, "GetProfile",
			fmt.Errorf("update tx auth details: get profile: %w", err))
	}

	authorizationDetailsSupplied := len(req.AuthorizationDetails) > 0
	requestedCredentialConfigurationIDs := make(map[string]struct{})

	if authorizationDetailsSupplied {
		if requestedCredentialConfigurationIDs, err = s.enrichTxCredentialConfigurationsWithAuthorizationDetails(
			profile,
			tx.CredentialConfiguration,
			req.AuthorizationDetails,
		); err != nil {
			s.sendFailedTransactionEvent(ctx, tx, err)
			return nil, err
		}
	}

	validScopes, err := s.checkScopes(
		profile, req.Scope, tx.Scope, tx.CredentialConfiguration, requestedCredentialConfigurationIDs)
	if err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)

		return nil, err
	}

	tx.Scope = validScopes

	// Delete unused keys from tx.CredentialConfiguration
	for credentialConfigurationID := range tx.CredentialConfiguration {
		if _, ok := requestedCredentialConfigurationIDs[credentialConfigurationID]; !ok {
			delete(tx.CredentialConfiguration, credentialConfigurationID)
		}
	}

	if err = s.store.Update(ctx, tx); err != nil {
		e := resterr.NewSystemError(resterr.TransactionStoreComponent, "Update", err)

		s.sendFailedTransactionEvent(ctx, tx, e)

		return nil, e
	}

	if err = s.sendIssuanceAuthRequestPreparedTxEvent(ctx, tx); err != nil {
		return nil, err
	}

	return &PrepareClaimDataAuthorizationResponse{
		ProfileID:                          tx.ProfileID,
		ProfileVersion:                     tx.ProfileVersion,
		TxID:                               tx.ID,
		ResponseType:                       tx.ResponseType,
		AuthorizationEndpoint:              tx.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: tx.PushedAuthorizationRequestEndpoint,
		// Use request-specific Scope to Issuer OIDC in order to request user consent for
		// specific scopes that were defined by Wallet.
		Scope: validScopes,
	}, nil
}

func (s *Service) prepareClaimDataAuthorizationRequestWalletInitiated(
	ctx context.Context,
	requestScopes []string,
	issuerURL string,
) (*PrepareClaimDataAuthorizationResponse, error) {
	sp := strings.Split(issuerURL, "/")
	if len(sp) < WalletInitFlowClaimExpectedMatchCount {
		logger.Error("invalid issuer url for wallet initiated flow", log.WithURL(issuerURL))
		return nil, resterr.ErrInvalidIssuerURL
	}

	profileID, profileVersion := sp[len(sp)-2], sp[len(sp)-1]

	profile, err := s.profileService.GetProfile(profileID, profileVersion)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, resterr.NewCustomError(resterr.ProfileNotFound, err)
		}

		return nil, resterr.NewSystemError(resterr.IssuerProfileSvcComponent, "GetProfile", err)
	}

	if profile.OIDCConfig == nil || !profile.OIDCConfig.WalletInitiatedAuthFlowSupported {
		return nil, errors.New("wallet initiated auth flow is not supported for current profile")
	}
	if profile.OIDCConfig.ClaimsEndpoint == "" {
		return nil, errors.New("empty claims endpoint for profile")
	}
	if len(profile.CredentialTemplates) == 0 {
		return nil, errors.New("no credential templates configured")
	}

	oidcConfig, err := s.wellKnownService.GetOIDCConfiguration(ctx, profile.OIDCConfig.IssuerWellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("wallet initiated flow get oidc config: %w", err)
	}

	credentialTemplateID := profile.CredentialTemplates[0].ID

	err = s.sendIssuanceAuthRequestPreparedEvent(
		ctx, profile, credentialTemplateID,
		true, oidcConfig.AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}

	return &PrepareClaimDataAuthorizationResponse{
		WalletInitiatedFlow: &common.WalletInitiatedFlowData{
			ProfileId:            profileID,
			ProfileVersion:       profileVersion,
			ClaimEndpoint:        profile.OIDCConfig.ClaimsEndpoint,
			CredentialTemplateId: credentialTemplateID,
			OpState:              uuid.NewString(),
			Scopes:               &requestScopes,
		},
		ProfileID:             profileID,
		ProfileVersion:        profileVersion,
		Scope:                 requestScopes,
		AuthorizationEndpoint: oidcConfig.AuthorizationEndpoint,
	}, nil
}

//nolint:gocognit,nolintlint
func (s *Service) enrichTxCredentialConfigurationsWithAuthorizationDetails(
	profile *profileapi.Issuer,
	txCredentialConfigurations map[string]*TxCredentialConfiguration,
	authorizationDetails []*AuthorizationDetails,
) (map[string]struct{}, error) {
	requestedCredentialConfigurationIDs := make(map[string]struct{})

	for _, ad := range authorizationDetails {
		switch {
		case ad.CredentialConfigurationID != "": // AuthorizationDetails contains CredentialConfigurationID.
			// Check for duplications.
			if _, ok := requestedCredentialConfigurationIDs[ad.CredentialConfigurationID]; ok {
				return nil, resterr.ErrInvalidCredentialConfigurationID
			}

			var metaCredentialsConfigurationSupported *profileapi.CredentialsConfigurationSupported
			if meta := profile.CredentialMetaData; meta != nil {
				metaCredentialsConfigurationSupported = meta.CredentialsConfigurationSupported[ad.CredentialConfigurationID]
			}

			// Check if ad.CredentialConfigurationID exists in issuer metadata.
			if metaCredentialsConfigurationSupported == nil {
				return nil, resterr.ErrInvalidCredentialConfigurationID
			}

			// Get txCredentialConfiguration based on ad.CredentialConfigurationID.
			txCredentialConfiguration, ok := txCredentialConfigurations[ad.CredentialConfigurationID]
			if !ok {
				return nil, resterr.ErrInvalidCredentialConfigurationID
			}

			if metaCredentialsConfigurationSupported.Format != txCredentialConfiguration.OIDCCredentialFormat {
				return nil, resterr.ErrCredentialFormatNotSupported
			}

			var targetType string
			if cd := metaCredentialsConfigurationSupported.CredentialDefinition; cd != nil {
				targetType = cd.Type[len(cd.Type)-1]
			}

			if !strings.EqualFold(targetType, txCredentialConfiguration.CredentialTemplate.Type) {
				return nil, resterr.ErrCredentialTypeNotSupported
			}

			txCredentialConfiguration.AuthorizationDetails = ad
			requestedCredentialConfigurationIDs[ad.CredentialConfigurationID] = struct{}{}
		case ad.Format != "": // AuthorizationDetails contains Format.
			var requestedCredentialFormatValid bool

			targetType := ad.CredentialDefinition.Type[len(ad.CredentialDefinition.Type)-1]

			for credentialConfigurationID, txCredentialConfig := range txCredentialConfigurations {
				if _, ok := requestedCredentialConfigurationIDs[credentialConfigurationID]; ok {
					// Do not consider already requested credentialConfigurationIDs.
					continue
				}

				if !strings.EqualFold(targetType, txCredentialConfig.CredentialTemplate.Type) {
					continue
				}

				if txCredentialConfig.OIDCCredentialFormat != ad.Format {
					continue
				}

				requestedCredentialFormatValid = true
				txCredentialConfig.AuthorizationDetails = ad
				requestedCredentialConfigurationIDs[credentialConfigurationID] = struct{}{}
				break
			}

			if !requestedCredentialFormatValid {
				return nil, resterr.ErrCredentialFormatNotSupported
			}
		default:
			return nil, resterr.NewValidationError(
				resterr.InvalidValue,
				"authorization_details",
				errors.New("neither credentialFormat nor credentialConfigurationID supplied"),
			)
		}
	}

	return requestedCredentialConfigurationIDs, nil
}

func (s *Service) ValidatePreAuthorizedCodeRequest( //nolint:gocognit,nolintlint
	ctx context.Context,
	preAuthorizedCode,
	pin,
	clientID,
	clientAssertionType,
	clientAssertion string,
) (*Transaction, error) {
	tx, err := s.store.FindByOpState(ctx, preAuthorizedCode)
	if err != nil {
		return nil, resterr.NewCustomError(resterr.OIDCTxNotFound, fmt.Errorf("find tx by op state: %w", err))
	}

	if len(pin) > 0 && len(tx.UserPin) == 0 {
		return nil, resterr.NewCustomError(resterr.OIDCPreAuthorizeDoesNotExpectPin,
			fmt.Errorf("server does not expect pin"))
	}

	if len(pin) == 0 && len(tx.UserPin) > 0 {
		return nil, resterr.NewCustomError(resterr.OIDCPreAuthorizeExpectPin,
			fmt.Errorf("server expects user pin"))
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, resterr.NewCustomError(resterr.ProfileNotFound, err)
		}

		return nil, resterr.NewSystemError(resterr.IssuerProfileSvcComponent, "GetProfile", err)
	}

	if clientID == "" { // check if anonymous access is allowed
		// profile.OIDCConfig is not required for pre-auth flow, so no specific error for this case.
		if profile.OIDCConfig != nil && !profile.OIDCConfig.PreAuthorizedGrantAnonymousAccessSupported {
			return nil, resterr.NewCustomError(resterr.OIDCPreAuthorizeInvalidClientID,
				fmt.Errorf("issuer does not accept Token Request with a Pre-Authorized Code but without a client_id"))
		}
	}

	newState := TransactionStatePreAuthCodeValidated
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		return nil, err
	}
	tx.State = newState

	for _, credentialConfiguration := range tx.CredentialConfiguration {
		if credentialConfiguration.PreAuthCodeExpiresAt.UTC().Before(time.Now().UTC()) {
			return nil, resterr.NewCustomError(resterr.OIDCTxNotFound, fmt.Errorf("invalid pre-authorization code"))
		}
	}

	if tx.PreAuthCode != preAuthorizedCode {
		return nil, resterr.NewCustomError(resterr.OIDCTxNotFound, fmt.Errorf("invalid pre-authorization code"))
	}

	if len(tx.UserPin) > 0 && !s.pinGenerator.Validate(tx.UserPin, pin) {
		return nil, resterr.NewCustomError(resterr.OIDCPreAuthorizeInvalidPin, fmt.Errorf("invalid pin"))
	}

	if err = s.checkPolicy(ctx, profile, tx, clientAssertionType, clientAssertion); err != nil {
		return nil, resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed, err)
	}

	if err = s.store.Update(ctx, tx); err != nil {
		return nil, err
	}

	if errSendEvent := s.sendTransactionEvent(ctx, tx, spi.IssuerOIDCInteractionQRScanned); errSendEvent != nil {
		return nil, errSendEvent
	}

	return tx, nil
}

func (s *Service) checkPolicy(
	ctx context.Context,
	profile *profileapi.Issuer,
	tx *Transaction,
	clientAssertionType,
	clientAssertion string,
) error {
	if profile.OIDCConfig != nil &&
		lo.Contains(profile.OIDCConfig.TokenEndpointAuthMethodsSupported, attestJWTClientAuthType) {
		if err := s.validateClientAssertionParams(clientAssertionType, clientAssertion); err != nil {
			return err
		}
	}

	if profile.Checks.Policy.PolicyURL != "" {
		var credentialTypes []string

		for _, credentialConfig := range tx.CredentialConfiguration {
			if credentialConfig.CredentialTemplate != nil {
				credentialTypes = append(credentialTypes, credentialConfig.CredentialTemplate.Type)
			}
		}

		if err := s.trustRegistry.ValidateIssuance(
			ctx,
			profile,
			&trustregistry.ValidateIssuanceData{
				AttestationVP:   clientAssertion,
				CredentialTypes: credentialTypes,
				Nonce:           tx.PreAuthCode,
			},
		); err != nil {
			return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed, err)
		}
	}

	return nil
}

func (s *Service) validateClientAssertionParams(clientAssertionType, clientAssertion string) error {
	if clientAssertionType == "" {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("no client assertion type specified"))
	}

	if clientAssertionType != attestJWTClientAuthType {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("only supported client assertion type is attest_jwt_client_auth"))
	}

	if clientAssertion == "" {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("client_assertion is required"))
	}

	return nil
}

func (s *Service) PrepareCredential( //nolint:funlen
	ctx context.Context,
	req *PrepareCredential,
) (*PrepareCredentialResult, error) {
	tx, err := s.store.Get(ctx, req.TxID)
	if err != nil {
		return nil, fmt.Errorf("get tx: %w", err)
	}

	prepareCredentialResult := &PrepareCredentialResult{
		ProfileID:      tx.ProfileID,
		ProfileVersion: tx.ProfileVersion,
		Credentials:    make([]*PrepareCredentialResultData, 0, len(req.CredentialRequests)),
	}

	for _, requestedCredential := range req.CredentialRequests {
		if err = s.validateRequestAudienceClaim(
			tx.ProfileID, tx.ProfileVersion, requestedCredential.AudienceClaim); err != nil {
			s.sendFailedTransactionEvent(ctx, tx, err)

			return nil, err
		}

		var txCredentialConfiguration *TxCredentialConfiguration
		txCredentialConfiguration, err = s.findTxCredentialConfiguration(
			tx.CredentialConfiguration,
			requestedCredential.CredentialFormat,
			requestedCredential.CredentialTypes,
		)
		if err != nil {
			s.sendFailedTransactionEvent(ctx, tx, err)

			return nil, err
		}

		cred, ackID, prepareCredError := s.prepareCredential(ctx, tx, txCredentialConfiguration, requestedCredential)
		if prepareCredError != nil {
			s.sendFailedTransactionEvent(ctx, tx, prepareCredError)

			return nil, prepareCredError
		}

		vcFormat, _ := common.ValidateVCFormat(common.VCFormat(txCredentialConfiguration.OIDCCredentialFormat))

		prepareCredentialResultData := &PrepareCredentialResultData{
			Credential:              cred,
			Format:                  vcFormat,
			OidcFormat:              txCredentialConfiguration.OIDCCredentialFormat,
			CredentialTemplate:      txCredentialConfiguration.CredentialTemplate,
			Retry:                   false,
			EnforceStrictValidation: txCredentialConfiguration.CredentialTemplate.Checks.Strict,
			NotificationID:          ackID,
		}

		prepareCredentialResult.Credentials = append(prepareCredentialResult.Credentials, prepareCredentialResultData)
	}

	tx.State = TransactionStateCredentialsIssued
	if err = s.store.Update(ctx, tx); err != nil {
		e := resterr.NewSystemError(resterr.TransactionStoreComponent, "Update", err)

		s.sendFailedTransactionEvent(ctx, tx, e)

		return nil, e
	}

	if errSendEvent := s.sendTransactionEvent(ctx, tx, spi.IssuerOIDCInteractionSucceeded); errSendEvent != nil {
		return nil, errSendEvent
	}

	return prepareCredentialResult, nil
}

func (s *Service) findTxCredentialConfiguration( //nolint:funlen
	txCredentialConfigurations map[string]*TxCredentialConfiguration,
	credentialFormat vcsverifiable.OIDCFormat,
	credentialTypes []string,
) (*TxCredentialConfiguration, error) {
	var txCredentialConfiguration *TxCredentialConfiguration
	for _, credentialConfiguration := range txCredentialConfigurations {
		if credentialConfiguration.OIDCCredentialFormat != credentialFormat {
			continue
		}

		if credentialConfiguration.CredentialTemplate == nil {
			return nil, resterr.ErrCredentialTemplateNotConfigured
		}

		if lo.Contains(credentialTypes, credentialConfiguration.CredentialTemplate.Type) {
			txCredentialConfiguration = credentialConfiguration
			break
		}
	}

	if txCredentialConfiguration == nil {
		return nil, resterr.NewCustomError(resterr.OIDCInvalidCredentialRequest,
			fmt.Errorf("tx credential configuration not found"))
	}

	return txCredentialConfiguration, nil
}

func (s *Service) validateRequestAudienceClaim( //nolint:funlen
	profileID profileapi.ID,
	profileVersion profileapi.Version,
	requestAudienceClaim string,
) error {
	expectedAudience := fmt.Sprintf("%s/oidc/idp/%s/%s", s.issuerVCSPublicHost, profileID, profileVersion)

	if requestAudienceClaim == "" || requestAudienceClaim != expectedAudience {
		return resterr.NewValidationError(resterr.InvalidOrMissingProofOIDCErr, requestAudienceClaim,
			errors.New("invalid aud"))
	}

	return nil
}

func (s *Service) prepareCredentialFromClaims(
	_ context.Context,
	claimData map[string]interface{},
	tx *Transaction,
	txCredentialConfiguration *TxCredentialConfiguration,
	prepareCredentialRequest *PrepareCredentialRequest,
) (*verifiable.Credential, error) {
	contexts := txCredentialConfiguration.CredentialTemplate.Contexts
	if len(contexts) == 0 {
		contexts = []string{defaultCtx}
	}

	// prepare credential for signing
	vcc := verifiable.CredentialContents{
		Context: contexts,
		ID:      uuid.New().URN(),
		Types:   []string{"VerifiableCredential", txCredentialConfiguration.CredentialTemplate.Type},
		Issuer:  &verifiable.Issuer{ID: tx.DID},
		Issued:  util.NewTime(time.Now()),
	}

	customFields := map[string]interface{}{}

	if txCredentialConfiguration.CredentialDescription != "" {
		customFields["description"] = txCredentialConfiguration.CredentialDescription
	}
	if txCredentialConfiguration.CredentialName != "" {
		customFields["name"] = txCredentialConfiguration.CredentialName
	}

	if txCredentialConfiguration.CredentialExpiresAt != nil {
		vcc.Expired = util.NewTime(*txCredentialConfiguration.CredentialExpiresAt)
	}

	if claimData != nil {
		vcc.Subject = []verifiable.Subject{{
			ID:           prepareCredentialRequest.DID,
			CustomFields: claimData,
		}}
	} else {
		vcc.Subject = []verifiable.Subject{{ID: prepareCredentialRequest.DID}}
	}

	return verifiable.CreateCredential(vcc, customFields)
}

func (s *Service) prepareCredentialFromCompose(
	ctx context.Context,
	claimData map[string]interface{},
	tx *Transaction,
	txCredentialConfiguration *TxCredentialConfiguration,
	req *PrepareCredentialRequest,
) (*verifiable.Credential, error) {
	cred, err := verifiable.ParseCredentialJSON(claimData,
		verifiable.WithCredDisableValidation(),
		verifiable.WithDisabledProofCheck(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse credential json: %w", err)
	}

	return s.composer.Compose(ctx, cred, tx, txCredentialConfiguration, req)
}

func (s *Service) prepareCredential( //nolint:funlen
	ctx context.Context,
	tx *Transaction,
	txCredentialConfiguration *TxCredentialConfiguration,
	prepareCredentialRequest *PrepareCredentialRequest,
) (*verifiable.Credential, *string, error) {
	claimData, err := s.getClaimsData(ctx, tx, txCredentialConfiguration)
	if err != nil {
		return nil, nil, fmt.Errorf("get claims data: %w", err)
	}

	var finalCred *verifiable.Credential

	switch txCredentialConfiguration.ClaimDataType {
	case ClaimDataTypeClaims:
		finalCred, err = s.prepareCredentialFromClaims(
			ctx,
			claimData,
			tx,
			txCredentialConfiguration,
			prepareCredentialRequest,
		)
	case ClaimDataTypeVC:
		finalCred, err = s.prepareCredentialFromCompose(
			ctx,
			claimData,
			tx,
			txCredentialConfiguration,
			prepareCredentialRequest,
		)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("prepare credential: %w", err)
	}

	// Create cpredential-specific record.
	ack, err := s.ackService.CreateAck(ctx, &Ack{
		HashedToken:    prepareCredentialRequest.HashedToken,
		ProfileID:      tx.ProfileID,
		ProfileVersion: tx.ProfileVersion,
		TxID:           generateAckTxID(tx.ID),
		WebHookURL:     tx.WebHookURL,
		OrgID:          tx.OrgID,
	})
	if err != nil { // its not critical and should not break the flow
		logger.Errorc(ctx, errors.Join(err, errors.New("can not create ack")).Error())
	}

	return finalCred, ack, nil
}

func (s *Service) getClaimsData(
	ctx context.Context,
	tx *Transaction,
	txCredentialConfiguration *TxCredentialConfiguration,
) (map[string]interface{}, error) {
	if !tx.IsPreAuthFlow {
		claims, err := s.requestClaims(ctx, tx, txCredentialConfiguration)
		if err != nil {
			return nil, resterr.NewSystemError(resterr.IssuerSvcComponent, "RequestClaims", err)
		}

		return claims, nil
	}

	tempClaimData, claimDataErr := s.claimDataStore.GetAndDelete(ctx, txCredentialConfiguration.ClaimDataID)
	if claimDataErr != nil {
		return nil, resterr.NewSystemError(resterr.ClaimDataStoreComponent, "GetAndDelete", claimDataErr)
	}

	decryptedClaims, decryptErr := s.DecryptClaims(ctx, tempClaimData)
	if decryptErr != nil {
		return nil, fmt.Errorf("decrypt claims: %w", decryptErr)
	}

	return decryptedClaims, nil
}

func (s *Service) requestClaims(
	ctx context.Context,
	tx *Transaction,
	txCredentialConfiguration *TxCredentialConfiguration,
) (map[string]interface{}, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, txCredentialConfiguration.ClaimEndpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	r.Header.Set("Authorization", "Bearer "+tx.IssuerToken)

	resp, err := s.httpClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, ioErr := io.ReadAll(resp.Body)
		if ioErr != nil {
			log.ReadRequestBodyError(logger, ioErr)
		} else {
			logger.Errorc(ctx, "Failed to fetch claims data",
				log.WithURL(txCredentialConfiguration.ClaimEndpoint),
				log.WithHTTPStatus(resp.StatusCode),
				log.WithResponse(b),
			)
		}

		return nil, fmt.Errorf("claim endpoint returned status code %d", resp.StatusCode)
	}

	var m map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode claim data: %w", err)
	}

	return m, nil
}

func createEvent(
	eventType spi.EventType,
	transactionID TxID,
	ep *EventPayload,
) (*spi.Event, error) {
	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	event := spi.NewEventWithPayload(uuid.NewString(), "source://vcs/issuer", eventType, payload)
	event.TransactionID = string(transactionID)

	return event, nil
}

func (s *Service) sendEvent(
	ctx context.Context,
	eventType spi.EventType,
	transactionID TxID,
	ep *EventPayload) error {
	event, err := createEvent(eventType, transactionID, ep)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
}

func (s *Service) sendTransactionEvent(
	ctx context.Context,
	tx *Transaction,
	eventType spi.EventType,
) error {
	return s.sendEvent(ctx, eventType, tx.ID, createTxEventPayload(tx))
}

func (s *Service) sendFailedTransactionEvent(
	ctx context.Context,
	tx *Transaction,
	e error,
) {
	ep := &EventPayload{
		WebHook:        tx.WebHookURL,
		ProfileID:      tx.ProfileID,
		ProfileVersion: tx.ProfileVersion,
		OrgID:          tx.OrgID,
	}

	ep.Error, ep.ErrorCode, ep.ErrorComponent = resterr.GetErrorDetails(e)

	if e := s.sendEvent(ctx, spi.IssuerOIDCInteractionFailed, tx.ID, ep); e != nil {
		logger.Warnc(ctx, "Failed to send OIDC issuer event. Ignoring..", log.WithError(e))
	}
}

func createTxEventPayload(tx *Transaction) *EventPayload {
	var (
		credentialTemplateID string
		credentialFormat     vcsverifiable.OIDCFormat
		oldParamsFilled      bool
	)

	credentialsData := map[string]vcsverifiable.OIDCFormat{}

	for _, txCredentialConf := range tx.CredentialConfiguration {
		var templateID string
		if txCredentialConf.CredentialTemplate != nil {
			templateID = txCredentialConf.CredentialTemplate.ID
		}

		if !oldParamsFilled {
			credentialTemplateID = templateID
			credentialFormat = txCredentialConf.OIDCCredentialFormat
			oldParamsFilled = true
		}

		credentialsData[templateID] = txCredentialConf.OIDCCredentialFormat
	}

	return &EventPayload{
		WebHook:              tx.WebHookURL,
		ProfileID:            tx.ProfileID,
		ProfileVersion:       tx.ProfileVersion,
		OrgID:                tx.OrgID,
		WalletInitiatedFlow:  tx.WalletInitiatedIssuance,
		CredentialTemplateID: credentialTemplateID,
		Format:               credentialFormat,
		PinRequired:          tx.UserPin != "",
		PreAuthFlow:          tx.IsPreAuthFlow,
		Credentials:          credentialsData,
	}
}

func (s *Service) sendInitiateIssuanceEvent(
	ctx context.Context,
	tx *Transaction,
	initiateURL string,
) error {
	payload := createTxEventPayload(tx)
	payload.InitiateIssuanceURL = initiateURL

	return s.sendEvent(ctx, spi.IssuerOIDCInteractionInitiated, tx.ID, payload)
}

func (s *Service) sendIssuanceAuthRequestPreparedTxEvent(
	ctx context.Context,
	tx *Transaction,
) error {
	payload := createTxEventPayload(tx)
	payload.AuthorizationEndpoint = tx.AuthorizationEndpoint

	return s.sendEvent(ctx, spi.IssuerOIDCInteractionAuthorizationRequestPrepared, tx.ID, payload)
}

func (s *Service) sendIssuanceAuthRequestPreparedEvent(
	ctx context.Context,
	profile *profileapi.Issuer,
	credTemplateID string,
	walletInitiatedFlow bool,
	authorizationEndpoint string,
) error {
	return s.sendEvent(ctx, spi.IssuerOIDCInteractionAuthorizationRequestPrepared,
		"", &EventPayload{
			WebHook:               profile.WebHook,
			ProfileID:             profile.ID,
			ProfileVersion:        profile.Version,
			OrgID:                 profile.OrganizationID,
			WalletInitiatedFlow:   walletInitiatedFlow,
			CredentialTemplateID:  credTemplateID,
			AuthorizationEndpoint: authorizationEndpoint,
			Credentials: map[string]vcsverifiable.OIDCFormat{
				credTemplateID: "",
			},
		},
	)
}
