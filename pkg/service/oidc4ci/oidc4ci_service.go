/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4ci_service_mocks_test.go -self_package mocks -package oidc4ci_test -source=oidc4ci_service.go -mock_names transactionStore=MockTransactionStore,wellKnownService=MockWellKnownService,eventService=MockEventService,pinGenerator=MockPinGenerator,credentialOfferReferenceStore=MockCredentialOfferReferenceStore,claimDataStore=MockClaimDataStore,profileService=MockProfileService,dataProtector=MockDataProtector,kmsRegistry=MockKMSRegistry,cryptoJWTSigner=MockCryptoJWTSigner,jsonSchemaValidator=MockJSONSchemaValidator,trustRegistry=MockTrustRegistry,ackStore=MockAckStore,ackService=MockAckService,composer=MockComposer,documentLoader=MockDocumentLoader

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
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"
	"go.uber.org/zap"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4cierr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4ci"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc6749"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/trustregistry"
)

const (
	defaultGrantType        = "authorization_code"
	defaultResponseType     = "token"
	attestJWTClientAuthType = "attest_jwt_client_auth"
)

var _ ServiceInterface = (*Service)(nil)

var logger = log.New("oidc4ci")

type pinGenerator interface {
	Generate(challenge string) string
	Validate(challenge string, userInput string) bool
}

type transactionStore interface {
	ForceCreate(
		ctx context.Context,
		profileTransactionDataTTL int32,
		data *issuecredential.TransactionData,
	) (*issuecredential.Transaction, error)

	Create(
		ctx context.Context,
		profileTransactionDataTTL int32,
		data *issuecredential.TransactionData,
	) (*issuecredential.Transaction, error)

	Get(
		ctx context.Context,
		txID issuecredential.TxID,
	) (*issuecredential.Transaction, error)

	FindByOpState(
		ctx context.Context,
		opState string,
	) (*issuecredential.Transaction, error)

	Update(
		ctx context.Context,
		tx *issuecredential.Transaction,
	) error
}

type claimDataStore interface {
	Create(ctx context.Context, profileTTLSec int32, data *issuecredential.ClaimData) (string, error)
	GetAndDelete(ctx context.Context, id string) (*issuecredential.ClaimData, error)
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
	Create(ctx context.Context, id string, profileAckDataTTL int32, data *Ack) error
	Get(ctx context.Context, id string) (*Ack, error)
	Delete(ctx context.Context, id string) error
	Update(ctx context.Context, id string, ack *Ack) error
}

type ackService interface {
	UpsertAck(ctx context.Context, ack *Ack) (string, error)
}

// DocumentLoader knows how to load remote documents.
type documentLoader interface {
	LoadDocument(u string) (*ld.RemoteDocument, error)
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
	DocumentLoader                documentLoader
	PrepareCredential             credentialIssuer
	WellKnownProvider             wellKnownProvider
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
	documentLoader                documentLoader
	credentialIssuer              credentialIssuer
	wellKnownProvider             wellKnownProvider
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
		documentLoader:                config.DocumentLoader,
		credentialIssuer:              config.PrepareCredential,
		wellKnownProvider:             config.WellKnownProvider,
	}, nil
}

func (s *Service) PushAuthorizationDetails(
	ctx context.Context,
	opState string,
	ad []*issuecredential.AuthorizationDetails,
) error {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return rfc6749.NewInvalidGrantError(err).WithErrorPrefix("find tx by op state")
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		return rfc6749.NewInvalidRequestError(err).WithErrorPrefix("getProfile")
	}

	var requestedTxCredentialConfigurationsIDs map[string]struct{}
	if requestedTxCredentialConfigurationsIDs, _, err = s.enrichTxCredentialConfigurationsWithAuthorizationDetails(
		profile,
		tx.CredentialConfiguration,
		ad,
	); err != nil {
		return rfc6749.NewInvalidRequestError(err)
	}

	var validTxCredentialConfiguration []*issuecredential.TxCredentialConfiguration
	// Delete unused entities from tx.CredentialConfiguration
	for _, txCredentialConfiguration := range tx.CredentialConfiguration {
		if _, ok := requestedTxCredentialConfigurationsIDs[txCredentialConfiguration.ID]; ok {
			validTxCredentialConfiguration = append(validTxCredentialConfiguration, txCredentialConfiguration)
		}
	}

	tx.CredentialConfiguration = validTxCredentialConfiguration

	if err = s.store.Update(ctx, tx); err != nil {
		return rfc6749.NewInvalidRequestError(err).WithErrorPrefix("update store")
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
	txCredentialConfigurations []*issuecredential.TxCredentialConfiguration,
	requestedTxCredentialConfigurationIDsViaAuthDetails map[string]struct{},
) ([]string, error) {
	var credentialsConfigurationSupported map[string]*profileapi.CredentialsConfigurationSupported
	if meta := profile.CredentialMetaData; meta != nil {
		credentialsConfigurationSupported = meta.CredentialsConfigurationSupported
	}

	var validScopes []string

	// Check each request scope.
	for _, reqScope := range reqScopes {
		if !lo.Contains(txScope, reqScope) {
			return nil, errors.New("invalid scope")
		}

		if !lo.Contains(profile.OIDCConfig.ScopesSupported, reqScope) {
			// Credential Issuers MUST ignore unknown scope values in a request.
			continue
		}

		validScopes = append(validScopes, reqScope)

		// Find metaCredentialConfiguration based on reqScope.
		for credentialConfigurationID, metaCredentialConfiguration := range credentialsConfigurationSupported {
			if !strings.EqualFold(reqScope, metaCredentialConfiguration.Scope) {
				continue
			}

			// On this moment credentialConfigurationID is found.

			// Iterate over all txCredentialConfigurations and find ones that was requsted using the scope.
			for _, txCredentialConfig := range txCredentialConfigurations {
				// If a scope value related to Credential issuance and the authorization_details request parameter
				// containing objects of type openid_credential are both present in a single request, the Credential Issuer MUST
				// interpret these individually. However, if both request the same Credential type, then the Credential Issuer MUST
				// follow the request as given by the authorization_details object.
				if _, ok := requestedTxCredentialConfigurationIDsViaAuthDetails[txCredentialConfig.ID]; ok {
					continue
				}

				if credentialConfigurationID != txCredentialConfig.CredentialConfigurationID {
					continue
				}

				// Check format.
				if metaCredentialConfiguration.Format != txCredentialConfig.OIDCCredentialFormat {
					continue
				}

				// Check credential type.
				var targetType string
				if cd := metaCredentialConfiguration.CredentialDefinition; cd != nil {
					targetType = cd.Type[len(cd.Type)-1]
				}

				if !strings.EqualFold(targetType, txCredentialConfig.CredentialTemplate.Type) {
					continue
				}

				requestedTxCredentialConfigurationIDsViaAuthDetails[txCredentialConfig.ID] = struct{}{}
			}
		}
	}

	return lo.Uniq(validScopes), nil
}

//nolint:funlen
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
		if walletFlowErr != nil && errors.Is(walletFlowErr, ErrInvalidIssuerURL) { // not wallet-initiated flow
			return nil, err
		}

		return walletFlowResp, walletFlowErr
	}

	if err != nil {
		return nil, err
	}

	newState := issuecredential.TransactionStateAwaitingIssuerOIDCAuthorization
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		s.sendFailedTransactionEvent(
			ctx, tx, err.Error(), resterr.InvalidStateTransition, resterr.IssuerOIDC4ciSvcComponent)
		return nil, err
	}

	tx.State = newState

	if req.ResponseType != tx.ResponseType {
		return nil, ErrResponseTypeMismatch
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, resterr.ErrProfileNotFound
		}

		return nil, fmt.Errorf("update tx auth details: get profile: %w", err)
	}

	authorizationDetailsSupplied := len(req.AuthorizationDetails) > 0
	requestedTxCredentialConfigurationIDs := make(map[string]struct{})

	if authorizationDetailsSupplied {
		var eventErrCode resterr.EventErrorCode
		if requestedTxCredentialConfigurationIDs, eventErrCode, err = s.enrichTxCredentialConfigurationsWithAuthorizationDetails( //nolint:lll
			profile,
			tx.CredentialConfiguration,
			req.AuthorizationDetails,
		); err != nil {
			s.sendFailedTransactionEvent(ctx, tx, err.Error(), eventErrCode, resterr.IssuerOIDC4ciSvcComponent)
			return nil, err
		}
	}

	validScopes, err := s.checkScopes(
		profile, req.Scope, tx.Scope, tx.CredentialConfiguration, requestedTxCredentialConfigurationIDs)
	if err != nil {
		e := rfc6749.NewInvalidScopeError(err).
			WithErrorPrefix("check scopes").
			WithComponent(resterr.IssuerOIDC4ciSvcComponent)

		s.sendFailedTransactionEvent(ctx, tx, e.Error(), e.Code(), resterr.IssuerOIDC4ciSvcComponent)

		return nil, e
	}

	tx.Scope = validScopes

	var validTxCredentialConfiguration []*issuecredential.TxCredentialConfiguration
	// Delete unused entities from tx.CredentialConfiguration
	for _, txCredentialConfiguration := range tx.CredentialConfiguration {
		if _, ok := requestedTxCredentialConfigurationIDs[txCredentialConfiguration.ID]; ok {
			validTxCredentialConfiguration = append(validTxCredentialConfiguration, txCredentialConfiguration)
		}
	}

	tx.CredentialConfiguration = validTxCredentialConfiguration

	if err = s.store.Update(ctx, tx); err != nil {
		e := fmt.Errorf("update store: %w", err)

		s.sendFailedTransactionEvent(ctx, tx, e.Error(), resterr.SystemError, resterr.TransactionStoreComponent)

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
		return nil, ErrInvalidIssuerURL
	}

	profileID, profileVersion := sp[len(sp)-2], sp[len(sp)-1]

	profile, err := s.profileService.GetProfile(profileID, profileVersion)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, resterr.ErrProfileNotFound
		}

		return nil, fmt.Errorf("get profile: %w", err)
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
	txCredentialConfigurations []*issuecredential.TxCredentialConfiguration,
	authorizationDetails []*issuecredential.AuthorizationDetails,
) (map[string]struct{}, resterr.EventErrorCode, error) {
	requestedTxCredentialConfigurationIDs := make(map[string]struct{})

	for _, ad := range authorizationDetails {
		switch {
		case ad.CredentialConfigurationID != "": // AuthorizationDetails contains CredentialConfigurationID.
			var metaCredentialsConfigurationSupported *profileapi.CredentialsConfigurationSupported
			if meta := profile.CredentialMetaData; meta != nil {
				metaCredentialsConfigurationSupported = meta.CredentialsConfigurationSupported[ad.CredentialConfigurationID]
			}

			// Check if ad.CredentialConfigurationID exists in issuer metadata.
			if metaCredentialsConfigurationSupported == nil {
				return nil, resterr.InvalidCredentialConfigurationID, ErrInvalidCredentialConfigurationID
			}

			var atLeastOneFound bool

			// Iterate over all txCredentialConfigurations and set AuthorizationDetails for ones
			// with the same ad.CredentialConfigurationID
			for _, txCredentialConfiguration := range txCredentialConfigurations {
				if txCredentialConfiguration.CredentialConfigurationID != ad.CredentialConfigurationID {
					continue
				}

				if metaCredentialsConfigurationSupported.Format != txCredentialConfiguration.OIDCCredentialFormat {
					return nil, resterr.CredentialFormatNotSupported, ErrCredentialFormatNotSupported
				}

				var targetType string
				if cd := metaCredentialsConfigurationSupported.CredentialDefinition; cd != nil {
					targetType = cd.Type[len(cd.Type)-1]
				}

				if !strings.EqualFold(targetType, txCredentialConfiguration.CredentialTemplate.Type) {
					return nil, resterr.CredentialTypeNotSupported, ErrCredentialTypeNotSupported
				}

				atLeastOneFound = true
				txCredentialConfiguration.AuthorizationDetails = ad
				requestedTxCredentialConfigurationIDs[txCredentialConfiguration.ID] = struct{}{}
			}

			if !atLeastOneFound {
				return nil, resterr.InvalidCredentialConfigurationID, ErrInvalidCredentialConfigurationID
			}
		case ad.Format != "": // AuthorizationDetails contains Format.
			var requestedCredentialFormatValid bool

			targetType := ad.CredentialDefinition.Type[len(ad.CredentialDefinition.Type)-1]

			// Iterate over all txCredentialConfigurations and set AuthorizationDetails for ones with the requested format + type
			for _, txCredentialConfig := range txCredentialConfigurations {
				if !strings.EqualFold(targetType, txCredentialConfig.CredentialTemplate.Type) {
					continue
				}

				if txCredentialConfig.OIDCCredentialFormat != ad.Format {
					continue
				}

				requestedCredentialFormatValid = true
				txCredentialConfig.AuthorizationDetails = ad
				requestedTxCredentialConfigurationIDs[txCredentialConfig.ID] = struct{}{}
			}

			if !requestedCredentialFormatValid {
				return nil, resterr.CredentialFormatNotSupported, ErrCredentialFormatNotSupported
			}
		default:
			return nil, resterr.InvalidValue, errors.New("neither credentialFormat nor credentialConfigurationID supplied")
		}
	}

	return requestedTxCredentialConfigurationIDs, "", nil
}

func (s *Service) ValidatePreAuthorizedCodeRequest( //nolint:gocognit,nolintlint
	ctx context.Context,
	preAuthorizedCode,
	pin,
	clientID,
	clientAssertionType,
	clientAssertion string,
) (*issuecredential.Transaction, error) {
	tx, err := s.store.FindByOpState(ctx, preAuthorizedCode)
	if err != nil {
		return nil, rfc6749.NewInvalidGrantError(err).WithErrorPrefix("find tx by op state")
	}

	if len(pin) > 0 && len(tx.UserPin) == 0 {
		return nil, rfc6749.NewInvalidRequestError(fmt.Errorf("server does not expect pin"))
	}

	if len(pin) == 0 && len(tx.UserPin) > 0 {
		return nil, rfc6749.NewInvalidRequestError(fmt.Errorf("server expects user pin"))
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		return nil, rfc6749.NewInvalidRequestError(err).WithErrorPrefix("getProfile")
	}

	if clientID == "" { // check if anonymous access is allowed
		// profile.OIDCConfig is not required for pre-auth flow, so no specific error for this case.
		if profile.OIDCConfig != nil && !profile.OIDCConfig.PreAuthorizedGrantAnonymousAccessSupported {
			return nil, rfc6749.NewInvalidClientError(
				fmt.Errorf("issuer does not accept Token Request with a Pre-Authorized Code but without a client_id"))
		}
	}

	newState := issuecredential.TransactionStatePreAuthCodeValidated
	if validationError := s.validateStateTransition(tx.State, newState); validationError != nil {
		return nil, rfc6749.NewInvalidRequestError(validationError)
	}

	tx.State = newState

	for _, credentialConfiguration := range tx.CredentialConfiguration {
		if credentialConfiguration.PreAuthCodeExpiresAt.UTC().Before(time.Now().UTC()) {
			return nil, rfc6749.NewInvalidGrantError(fmt.Errorf("invalid pre-authorization code"))
		}
	}

	if tx.PreAuthCode != preAuthorizedCode {
		return nil, rfc6749.NewInvalidGrantError(fmt.Errorf("invalid pre-authorization code"))
	}

	if len(tx.UserPin) > 0 && !s.pinGenerator.Validate(tx.UserPin, pin) {
		return nil, rfc6749.NewInvalidGrantError(fmt.Errorf("invalid pin"))
	}

	if err = s.checkPolicy(ctx, profile, tx, clientAssertionType, clientAssertion); err != nil {
		return nil, rfc6749.NewInvalidRequestError(err).WithErrorPrefix("check policy")
	}

	if err = s.store.Update(ctx, tx); err != nil {
		return nil, rfc6749.NewInvalidRequestError(err).WithErrorPrefix("update store")
	}

	if errSendEvent := s.sendTransactionEvent(
		ctx,
		tx,
		spi.IssuerOIDCInteractionQRScanned,
		nil,
	); errSendEvent != nil {
		return nil, rfc6749.NewInvalidRequestError(errSendEvent).WithErrorPrefix("send transaction event")
	}

	return tx, nil
}

func (s *Service) checkPolicy(
	ctx context.Context,
	profile *profileapi.Issuer,
	tx *issuecredential.Transaction,
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
			return fmt.Errorf("validate issuance: %w", err)
		}
	}

	return nil
}

func (s *Service) validateClientAssertionParams(clientAssertionType, clientAssertion string) error {
	if clientAssertionType == "" {
		return errors.New("no client assertion type specified")
	}

	if clientAssertionType != attestJWTClientAuthType {
		return errors.New("only supported client assertion type is attest_jwt_client_auth")
	}

	if clientAssertion == "" {
		return errors.New("client_assertion is required")
	}

	return nil
}

func (s *Service) PrepareCredential( //nolint:funlen
	ctx context.Context,
	req *PrepareCredential,
) (*PrepareCredentialResult, error) {
	tx, getTxErr := s.store.Get(ctx, req.TxID)
	if getTxErr != nil {
		return nil, oidc4cierr.NewInvalidCredentialRequestError(getTxErr).
			WithErrorPrefix("get tx")
	}

	prepareCredentialResult := &PrepareCredentialResult{
		ProfileID:      tx.ProfileID,
		ProfileVersion: tx.ProfileVersion,
		Credentials:    make([]*PrepareCredentialResultData, 0, len(req.CredentialRequests)),
	}

	requestedTxCredentialConfigurationIDs := make(map[string]struct{})

	var credentialIDs []string

	for _, requestedCredential := range req.CredentialRequests {
		if validationErr := s.validateRequestAudienceClaim(
			tx.ProfileID, tx.ProfileVersion, requestedCredential.AudienceClaim); validationErr != nil {
			s.sendFailedTransactionEvent(ctx, tx, validationErr.Error(), validationErr.Code(), validationErr.ErrorComponent)

			return nil, validationErr
		}

		txCredentialConfiguration, err := s.findTxCredentialConfiguration(
			requestedTxCredentialConfigurationIDs,
			tx.CredentialConfiguration,
			requestedCredential.CredentialFormat,
			requestedCredential.CredentialTypes,
		)
		if err != nil {
			e := oidc4cierr.NewInvalidCredentialRequestError(err).
				WithErrorPrefix("find tx credential configuration").
				WithComponent(resterr.IssuerOIDC4ciSvcComponent)

			s.sendFailedTransactionEvent(ctx, tx, e.Error(), e.Code(), e.ErrorComponent)

			return nil, e
		}

		requestedTxCredentialConfigurationIDs[txCredentialConfiguration.ID] = struct{}{}

		cred, prepareCredError := s.prepareCredential(ctx, tx, txCredentialConfiguration, requestedCredential)
		if prepareCredError != nil {
			e := oidc4cierr.NewInvalidCredentialRequestError(prepareCredError).
				WithErrorPrefix("prepare credential").
				WithComponent(resterr.IssuerOIDC4ciSvcComponent)

			s.sendFailedTransactionEvent(ctx, tx, e.Error(), e.Code(), e.ErrorComponent)

			return nil, e
		}

		vcFormat, _ := common.ValidateVCFormat(common.VCFormat(txCredentialConfiguration.OIDCCredentialFormat))

		prepareCredentialResultData := &PrepareCredentialResultData{
			Credential:              cred,
			Format:                  vcFormat,
			OidcFormat:              txCredentialConfiguration.OIDCCredentialFormat,
			CredentialTemplate:      txCredentialConfiguration.CredentialTemplate,
			Retry:                   false,
			EnforceStrictValidation: txCredentialConfiguration.CredentialTemplate.Checks.Strict,
		}

		credentialIDs = append(credentialIDs, cred.Contents().ID)
		prepareCredentialResult.Credentials = append(prepareCredentialResult.Credentials, prepareCredentialResultData)
	}

	if credentialsIssued := len(prepareCredentialResult.Credentials); credentialsIssued > 0 {
		var upserErr error

		prepareCredentialResult.NotificationID, upserErr = s.ackService.UpsertAck(ctx, &Ack{
			TxID:              tx.ID,
			HashedToken:       req.HashedToken,
			ProfileID:         tx.ProfileID,
			ProfileVersion:    tx.ProfileVersion,
			WebHookURL:        tx.WebHookURL,
			OrgID:             tx.OrgID,
			CredentialsIssued: credentialsIssued,
		})
		if upserErr != nil { // its not critical and should not break the flow
			logger.Errorc(ctx, errors.Join(upserErr, errors.New("can not create ack")).Error())
		}
	}

	tx.State = issuecredential.TransactionStateCredentialsIssued
	if err := s.store.Update(ctx, tx); err != nil {
		e := oidc4cierr.NewInvalidCredentialRequestError(err).
			WithOperation("Update").
			WithComponent(resterr.TransactionStoreComponent)

		s.sendFailedTransactionEvent(ctx, tx, e.Error(), e.Code(), e.ErrorComponent)

		return nil, e
	}

	if errSendEvent := s.sendTransactionEvent(
		ctx,
		tx,
		spi.IssuerOIDCInteractionSucceeded,
		credentialIDs,
	); errSendEvent != nil {
		return nil, oidc4cierr.NewInvalidCredentialRequestError(errSendEvent)
	}

	return prepareCredentialResult, nil
}

func (s *Service) prepareCredential( //nolint:funlen
	ctx context.Context,
	tx *issuecredential.Transaction,
	txCredentialConfiguration *issuecredential.TxCredentialConfiguration,
	prepareCredentialRequest *PrepareCredentialRequest,
) (*verifiable.Credential, error) {
	claimData, err := s.getClaimsData(ctx, tx, txCredentialConfiguration)
	if err != nil {
		return nil, fmt.Errorf("get claims data: %w", err)
	}

	finalCred, err := s.credentialIssuer.PrepareCredential(ctx, &issuecredential.PrepareCredentialsRequest{
		TxID:                    string(tx.ID),
		ClaimData:               claimData,
		IssuerDID:               tx.DID,
		SubjectDID:              prepareCredentialRequest.DID,
		CredentialConfiguration: txCredentialConfiguration,
		IssuerID:                tx.ProfileID,
		IssuerVersion:           tx.ProfileVersion,
		RefreshServiceEnabled:   tx.RefreshServiceEnabled,
	})
	if err != nil {
		return nil, fmt.Errorf("PrepareCredential: %w", err)
	}

	return finalCred, nil
}

func (s *Service) findTxCredentialConfiguration( //nolint:funlen
	requestedTxCredentialConfigurationIDs map[string]struct{},
	txCredentialConfigurations []*issuecredential.TxCredentialConfiguration,
	credentialFormat vcsverifiable.OIDCFormat,
	credentialTypes []string,
) (*issuecredential.TxCredentialConfiguration, error) {
	var txCredentialConfiguration *issuecredential.TxCredentialConfiguration
	for _, credentialConfiguration := range txCredentialConfigurations {
		if _, ok := requestedTxCredentialConfigurationIDs[credentialConfiguration.ID]; ok {
			continue
		}

		if credentialConfiguration.OIDCCredentialFormat != credentialFormat {
			continue
		}

		if credentialConfiguration.CredentialTemplate == nil {
			return nil, errors.New("credential template not configured")
		}

		if lo.Contains(credentialTypes, credentialConfiguration.CredentialTemplate.Type) {
			txCredentialConfiguration = credentialConfiguration
			break
		}
	}

	if txCredentialConfiguration == nil {
		return nil, fmt.Errorf("tx credential configuration not found")
	}

	return txCredentialConfiguration, nil
}

func (s *Service) validateRequestAudienceClaim( //nolint:funlen
	profileID profileapi.ID,
	profileVersion profileapi.Version,
	requestAudienceClaim string,
) *oidc4cierr.Error {
	expectedAudience := fmt.Sprintf("%s/oidc/idp/%s/%s", s.issuerVCSPublicHost, profileID, profileVersion)

	if requestAudienceClaim == "" || requestAudienceClaim != expectedAudience {
		return oidc4cierr.NewInvalidCredentialRequestError(errors.New("invalid aud"))
	}

	return nil
}

func (s *Service) getClaimsData(
	ctx context.Context,
	tx *issuecredential.Transaction,
	txCredentialConfiguration *issuecredential.TxCredentialConfiguration,
) (map[string]interface{}, error) {
	if !tx.IsPreAuthFlow {
		claims, err := s.requestClaims(ctx, tx, txCredentialConfiguration)
		if err != nil {
			return nil, fmt.Errorf("request claims: %w", err)
		}

		return claims, nil
	}

	tempClaimData, claimDataErr := s.claimDataStore.GetAndDelete(ctx, txCredentialConfiguration.ClaimDataID)
	if claimDataErr != nil {
		return nil, fmt.Errorf("get and delete: %w", claimDataErr)
	}

	decryptedClaims, decryptErr := s.DecryptClaims(ctx, tempClaimData)
	if decryptErr != nil {
		return nil, fmt.Errorf("decrypt claims: %w", decryptErr)
	}

	return decryptedClaims, nil
}

func (s *Service) requestClaims(
	ctx context.Context,
	tx *issuecredential.Transaction,
	txCredentialConfiguration *issuecredential.TxCredentialConfiguration,
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
	transactionID issuecredential.TxID,
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
	transactionID issuecredential.TxID,
	ep *EventPayload) error {
	event, err := createEvent(eventType, transactionID, ep)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
}

func (s *Service) sendTransactionEvent(
	ctx context.Context,
	tx *issuecredential.Transaction,
	eventType spi.EventType,
	credentialIDs []string,
) error {
	return s.sendEvent(ctx, eventType, tx.ID, createTxEventPayload(tx, credentialIDs))
}

func (s *Service) sendFailedTransactionEvent(
	ctx context.Context,
	tx *issuecredential.Transaction,
	errorStr string,
	errorCode resterr.EventErrorCode,
	component resterr.Component,
) {
	ep := &EventPayload{
		WebHook:        tx.WebHookURL,
		ProfileID:      tx.ProfileID,
		ProfileVersion: tx.ProfileVersion,
		OrgID:          tx.OrgID,
		Error:          errorStr,
		ErrorCode:      errorCode,
		ErrorComponent: string(component),
	}

	if err := s.sendEvent(ctx, spi.IssuerOIDCInteractionFailed, tx.ID, ep); err != nil {
		logger.Warnc(ctx, "Failed to send OIDC issuer event. Ignoring..", zap.String("error", errorStr))
	}
}

func createTxEventPayload(
	tx *issuecredential.Transaction,
	credentialIDs []string,
) *EventPayload {
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
		CredentialIDs:        credentialIDs,
	}
}

func (s *Service) sendInitiateIssuanceEvent(
	ctx context.Context,
	tx *issuecredential.Transaction,
	initiateURL string,
) error {
	payload := createTxEventPayload(tx, nil)
	payload.InitiateIssuanceURL = initiateURL

	return s.sendEvent(ctx, spi.IssuerOIDCInteractionInitiated, tx.ID, payload)
}

func (s *Service) sendIssuanceAuthRequestPreparedTxEvent(
	ctx context.Context,
	tx *issuecredential.Transaction,
) error {
	payload := createTxEventPayload(tx, nil)
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
