/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4vp_service_mocks_test.go -self_package mocks -package oidc4vp_test -source=oidc4vp_service.go -mock_names transactionManager=MockTransactionManager,events=MockEvents,kmsRegistry=MockKMSRegistry,requestObjectPublicStore=MockRequestObjectPublicStore,profileService=MockProfileService,presentationVerifier=MockPresentationVerifier,trustRegistry=MockTrustRegistry

package oidc4vp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/doc/jose"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/suite/ecdsa2019"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vc-go/vermethod"
	"github.com/valyala/fastjson"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	noopMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/noop"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/trustregistry"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

var logger = log.New("oidc4vp-service")

const (
	vpSubmissionProperty = "presentation_submission"
	customScopeProperty  = "_scope"
)

const (
	additionalClaimFieldName        = "name"
	additionalClaimFieldDesc        = "description"
	additionalClaimFieldAwardedDate = "awardedDate"
)

var ErrDataNotFound = errors.New("data not found")

type eventService interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type transactionManager interface {
	CreateTx(
		pd *presexch.PresentationDefinition,
		profileID, profileVersion string,
		profileTransactionDataTTL int32,
		profileNonceStoreDataTTL int32,
		customScopes []string) (*Transaction, string, error)
	StoreReceivedClaims(
		txID TxID,
		claims *ReceivedClaims,
		profileTransactionDataTTL int32,
		profileReceivedClaimsDataTTL int32,
	) error
	DeleteReceivedClaims(claimsID string) error
	GetByOneTimeToken(nonce string) (*Transaction, bool, error)
	Get(txID TxID) (*Transaction, error)
}

type requestObjectPublicStore interface {
	Publish(ctx context.Context, requestObject string) (string, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Verifier, error)
}

type presentationVerifier interface {
	VerifyPresentation(
		ctx context.Context,
		presentation *verifiable.Presentation,
		opts *verifypresentation.Options,
		profile *profileapi.Verifier,
	) (
		[]verifypresentation.PresentationVerificationCheckResult, map[string][]string, error,
	)
}

type trustRegistry interface {
	trustregistry.ValidatePresentation
}

type RequestObjectClaims struct {
	VPToken VPToken `json:"vp_token"`
}
type VPToken struct {
	PresentationDefinition *presexch.PresentationDefinition `json:"presentation_definition"`
}

// RequestObject represents the request object sent to the wallet. It contains the presentation definition
// that specifies what verifiable credentials should be sent back by the wallet.
type RequestObject struct {
	JTI          string                    `json:"jti"`
	IAT          int64                     `json:"iat"`
	ISS          string                    `json:"iss"`
	ResponseType string                    `json:"response_type"`
	ResponseMode string                    `json:"response_mode"`
	Scope        string                    `json:"scope"`
	Nonce        string                    `json:"nonce"`
	ClientID     string                    `json:"client_id"`
	RedirectURI  string                    `json:"redirect_uri"`
	State        string                    `json:"state"`
	Exp          int64                     `json:"exp"`
	Registration RequestObjectRegistration `json:"registration"`
	Claims       RequestObjectClaims       `json:"claims"`
}

type Config struct {
	TransactionManager       transactionManager
	RequestObjectPublicStore requestObjectPublicStore
	KMSRegistry              kmsRegistry
	DocumentLoader           ld.DocumentLoader
	ProfileService           profileService
	EventSvc                 eventService
	EventTopic               string
	PresentationVerifier     presentationVerifier
	VDR                      vdrapi.Registry
	TrustRegistry            trustRegistry

	RedirectURL   string
	TokenLifetime time.Duration
	Metrics       metricsProvider
}

type metricsProvider interface {
	VerifyOIDCVerifiablePresentationTime(value time.Duration)
}

type Service struct {
	eventSvc                 eventService
	eventTopic               string
	transactionManager       transactionManager
	requestObjectPublicStore requestObjectPublicStore
	kmsRegistry              kmsRegistry
	documentLoader           ld.DocumentLoader
	profileService           profileService
	presentationVerifier     presentationVerifier
	vdr                      vdrapi.Registry
	trustRegistry            trustRegistry

	redirectURL   string
	tokenLifetime time.Duration

	metrics metricsProvider
}

type RequestObjectRegistration struct {
	ClientName                  string           `json:"client_name"`
	SubjectSyntaxTypesSupported []string         `json:"subject_syntax_types_supported"`
	VPFormats                   *presexch.Format `json:"vp_formats"`
	ClientPurpose               string           `json:"client_purpose"`
	LogoURI                     string           `json:"logo_uri"`
}

func NewService(cfg *Config) *Service {
	metrics := cfg.Metrics

	if metrics == nil {
		metrics = &noopMetricsProvider.NoMetrics{}
	}

	return &Service{
		eventSvc:                 cfg.EventSvc,
		eventTopic:               cfg.EventTopic,
		transactionManager:       cfg.TransactionManager,
		requestObjectPublicStore: cfg.RequestObjectPublicStore,
		kmsRegistry:              cfg.KMSRegistry,
		documentLoader:           cfg.DocumentLoader,
		profileService:           cfg.ProfileService,
		presentationVerifier:     cfg.PresentationVerifier,
		redirectURL:              cfg.RedirectURL,
		tokenLifetime:            cfg.TokenLifetime,
		vdr:                      cfg.VDR,
		trustRegistry:            cfg.TrustRegistry,
		metrics:                  metrics,
	}
}

func (s *Service) sendTxEvent(
	ctx context.Context,
	eventType spi.EventType,
	tx *Transaction,
	profile *profileapi.Verifier,
) error {
	event, err := CreateEvent(eventType, tx.ID, createTxEventPayload(tx, profile))
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
}

func (s *Service) sendOIDCInteractionInitiatedEvent(
	ctx context.Context,
	tx *Transaction,
	profile *profileapi.Verifier,
	authorizationRequest string,
) error {
	ep := createTxEventPayload(tx, profile)
	ep.AuthorizationRequest = authorizationRequest
	ep.Filter = getFilter(tx.PresentationDefinition)

	event, err := CreateEvent(spi.VerifierOIDCInteractionInitiated, tx.ID, ep)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
}

func (s *Service) sendFailedTransactionEvent(
	ctx context.Context,
	tx *Transaction,
	profile *profileapi.Verifier,
	e error,
) {
	ep := createTxEventPayload(tx, profile)
	ep.Error, ep.ErrorCode, ep.ErrorComponent = resterr.GetErrorDetails(e)

	event, e := CreateEvent(spi.VerifierOIDCInteractionFailed, tx.ID, ep)
	if e != nil {
		logger.Warnc(ctx, "Failed to send OIDC verifier event. Ignoring..", log.WithError(e))
	}

	if e := s.eventSvc.Publish(ctx, s.eventTopic, event); e != nil {
		logger.Warnc(ctx, "Failed to send OIDC verifier event. Ignoring..", log.WithError(e))
	}
}

func (s *Service) InitiateOidcInteraction(
	ctx context.Context,
	presentationDefinition *presexch.PresentationDefinition,
	purpose string,
	customScopes []string,
	profile *profileapi.Verifier,
) (*InteractionInfo, error) {
	logger.Debugc(ctx, "InitiateOidcInteraction begin")

	if profile.SigningDID == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "profile.SigningDID",
			errors.New("profile signing did can't be nil"))
	}

	tx, nonce, err := s.transactionManager.CreateTx(
		presentationDefinition,
		profile.ID,
		profile.Version,
		profile.DataConfig.OIDC4VPTransactionDataTTL,
		profile.DataConfig.OIDC4VPNonceStoreDataTTL,
		customScopes,
	)
	if err != nil {
		return nil, resterr.NewSystemError(resterr.VerifierTxnMgrComponent, "create-txn",
			fmt.Errorf("fail to create oidc tx: %w", err))
	}

	logger.Debugc(ctx, "InitiateOidcInteraction tx created", log.WithTxID(string(tx.ID)))

	token, err := s.createRequestObjectJWT(presentationDefinition, tx, nonce, purpose, customScopes, profile)
	if err != nil {
		s.sendFailedTransactionEvent(ctx, tx, profile, err)

		return nil, err
	}

	logger.Debugc(ctx, "InitiateOidcInteraction request object created")

	requestURI, err := s.requestObjectPublicStore.Publish(ctx, token)
	if err != nil {
		e := fmt.Errorf("failed to publish request object: %w", err)

		s.sendFailedTransactionEvent(ctx, tx, profile, e)

		return nil, e
	}

	logger.Debugc(ctx, "InitiateOidcInteraction request object published")

	authorizationRequest := "openid-vc://?request_uri=" + requestURI

	if errSendEvent := s.sendOIDCInteractionInitiatedEvent(ctx, tx, profile, authorizationRequest); errSendEvent != nil {
		return nil, errSendEvent
	}

	logger.Debugc(ctx, "InitiateOidcInteraction succeed")

	return &InteractionInfo{
		AuthorizationRequest: authorizationRequest,
		TxID:                 tx.ID,
	}, nil
}

func (s *Service) verifyTokens(
	ctx context.Context,
	tx *Transaction,
	profile *profileapi.Verifier,
	tokens []*ProcessedVPToken,
) (map[string]*ProcessedVPToken, error) {
	verifiedPresentations := make(map[string]*ProcessedVPToken)

	var validationErrors []error
	mut := sync.Mutex{}
	wg := sync.WaitGroup{}
	for _, token2 := range tokens {
		token := token2
		wg.Add(1)

		go func() {
			defer wg.Done()
			if !lo.Contains(profile.Checks.Presentation.Format, token.VpTokenFormat) {
				e := resterr.NewValidationError(resterr.InvalidValue, "format",
					fmt.Errorf("profile does not support %s vp_token format", token.VpTokenFormat))

				mut.Lock()
				validationErrors = append(validationErrors, e)
				mut.Unlock()
				return
			}

			vr, _, innerErr := s.presentationVerifier.VerifyPresentation(ctx, token.Presentation, &verifypresentation.Options{
				Domain:    token.ClientID,
				Challenge: token.Nonce,
			}, profile)
			if innerErr != nil {
				e := resterr.NewSystemError(resterr.VerifierPresentationVerifierComponent, "verify-presentation",
					fmt.Errorf("presentation verification failed: %w", innerErr))

				mut.Lock()
				validationErrors = append(validationErrors, e)
				mut.Unlock()
				return
			}

			if len(vr) > 0 {
				e := resterr.NewCustomError(resterr.PresentationVerificationFailed,
					fmt.Errorf("presentation verification checks failed: %s", vr[0].Error))

				mut.Lock()
				validationErrors = append(validationErrors, e)
				mut.Unlock()
				return
			}

			mut.Lock()
			defer mut.Unlock()
			if _, ok := verifiedPresentations[token.Presentation.ID]; !ok {
				verifiedPresentations[token.Presentation.ID] = token
			} else {
				e := resterr.NewCustomError(resterr.DuplicatePresentationID,
					fmt.Errorf("duplicate presentation ID: %s", token.Presentation.ID))

				validationErrors = append(validationErrors, e)
				return
			}
		}()
		logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation verified")
	}
	wg.Wait()

	if len(validationErrors) > 0 {
		err := validationErrors[0]

		s.sendFailedTransactionEvent(ctx, tx, profile, err)

		return nil, err
	}

	return verifiedPresentations, nil
}

//nolint:funlen
func (s *Service) VerifyOIDCVerifiablePresentation(
	ctx context.Context,
	txID TxID,
	authResponse *AuthorizationResponseParsed,
) error {
	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation begin")
	startTime := time.Now()

	defer func() {
		logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation", log.WithDuration(time.Since(startTime)))
	}()

	if len(authResponse.VPTokens) == 0 {
		// this should never happen
		return resterr.NewValidationError(resterr.InvalidValue, "tokens",
			fmt.Errorf("must have at least one token"))
	}

	// All tokens have same nonce
	tx, validNonce, err := s.transactionManager.GetByOneTimeToken(authResponse.VPTokens[0].Nonce)
	if err != nil {
		return resterr.NewSystemError(resterr.VerifierTxnMgrComponent, "get-by-one-time-token",
			fmt.Errorf("get tx by nonce failed: %w", err))
	}

	if !validNonce || tx.ID != txID {
		return resterr.NewValidationError(resterr.InvalidValue, "nonce",
			fmt.Errorf("invalid nonce"))
	}

	// If amount custom scopes is not equal to amount of supplied claims.
	unexpectedClaimsAmount := len(tx.CustomScopes) != len(authResponse.CustomScopeClaims)
	// If no additional claims supplied for any of custom scopes.
	_, noAdditionalClaimsSupplied := lo.Find(tx.CustomScopes, func(item string) bool {
		val, ok := authResponse.CustomScopeClaims[item]

		return !ok || len(val) == 0
	})

	if unexpectedClaimsAmount || noAdditionalClaimsSupplied {
		return resterr.NewValidationError(resterr.InvalidValue, "_scope",
			fmt.Errorf("invalid _scope"))
	}

	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation nonce verified")

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		return resterr.NewValidationError(resterr.ConditionNotMet, "profile",
			fmt.Errorf("inconsistent transaction state %w", err))
	}

	if errSendEvent := s.sendTxEvent(ctx, spi.VerifierOIDCInteractionQRScanned, tx, profile); errSendEvent != nil {
		return errSendEvent
	}

	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation profile fetched", logfields.WithProfileID(profile.ID))

	policyChan := make(chan error)
	go func() {
		defer close(policyChan)
		policyChan <- s.checkPolicy(ctx, profile, authResponse.AttestationVP, authResponse.VPTokens)
	}()

	logger.Debugc(ctx, fmt.Sprintf("VerifyOIDCVerifiablePresentation count of tokens is %v", len(authResponse.VPTokens)))

	verifiedPresentations, err := s.verifyTokens(ctx, tx, profile, authResponse.VPTokens)
	if err != nil {
		return err
	}

	if policyErr := <-policyChan; policyErr != nil {
		return policyErr
	}

	receivedClaims, err := s.extractClaimData(ctx, tx, authResponse, profile, verifiedPresentations)
	if err != nil {
		s.sendFailedTransactionEvent(ctx, tx, profile, err)

		return err
	}

	err = s.transactionManager.StoreReceivedClaims(
		tx.ID,
		receivedClaims,
		profile.DataConfig.OIDC4VPTransactionDataTTL,
		profile.DataConfig.OIDC4VPReceivedClaimsDataTTL,
	)
	if err != nil {
		s.sendFailedTransactionEvent(ctx, tx, profile, err)

		return resterr.NewSystemError(resterr.VerifierTxnMgrComponent, "store-received-claims",
			fmt.Errorf("store received claims: %w", err))
	}

	logger.Debugc(ctx, "extractClaimData claims stored")

	err = s.sendOIDCInteractionEvent(ctx, spi.VerifierOIDCInteractionSucceeded, tx, profile, receivedClaims)
	if err != nil {
		return err
	}

	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation succeed")
	return nil
}

func (s *Service) checkPolicy(
	ctx context.Context,
	profile *profileapi.Verifier,
	attestationVP string,
	vpTokens []*ProcessedVPToken,
) error {
	if profile.Checks.Policy.PolicyURL == "" {
		return nil
	}

	st := time.Now()

	matches := make([]trustregistry.CredentialMatches, 0)

	for _, token := range vpTokens {
		for _, credential := range token.Presentation.Credentials() {
			vcc := credential.Contents()

			var iss, exp string

			if vcc.Issued != nil {
				iss = vcc.Issued.FormatToString()
			}

			if vcc.Expired != nil {
				exp = vcc.Expired.FormatToString()
			}

			matches = append(matches, trustregistry.CredentialMatches{
				CredentialID: vcc.ID,
				Types:        vcc.Types,
				IssuerID:     vcc.Issuer.ID,
				Issued:       iss,
				Expired:      exp,
			})
		}
	}

	if err := s.trustRegistry.ValidatePresentation(
		ctx,
		profile,
		&trustregistry.ValidatePresentationData{
			AttestationVP:     attestationVP,
			CredentialMatches: matches,
		},
	); err != nil {
		return fmt.Errorf("check policy: %w", err)
	}

	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation policy checked",
		logfields.WithProfileID(profile.ID),
		log.WithDuration(time.Since(st)),
	)

	return nil
}

func (s *Service) GetTx(_ context.Context, id TxID) (*Transaction, error) {
	return s.transactionManager.Get(id)
}

func (s *Service) RetrieveClaims(
	ctx context.Context,
	tx *Transaction,
	profile *profileapi.Verifier,
) map[string]CredentialMetadata {
	logger.Debugc(ctx, "RetrieveClaims begin")
	result := map[string]CredentialMetadata{}

	for _, cred := range tx.ReceivedClaims.Credentials {
		credType := vcsverifiable.Ldp
		if cred.IsJWT() {
			credType = vcsverifiable.Jwt
		}

		var err error
		// Creating display credential.
		// For regular credentials (JWT and JSON-LD) this func will do nothing,
		// but for SD-JWT case it returns verifiable.Credential with disclosed subject claims.
		cred, err = cred.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
		if err != nil {
			logger.Debugc(ctx, "RetrieveClaims - failed to CreateDisplayCredential", log.WithError(err))
			continue
		}
		credContents := cred.Contents()

		// TODO: review this code change. This code shouldn't be dependent on how vc-go serialize
		// issuer and subject into credential. It has complicated logic like serialize as just string if issuer
		// have only id. Any changes or extension of how vc works will affect some internal code, that should be
		// isolated from this kind of changes.
		subject := lo.Map(credContents.Subject, func(subj verifiable.Subject, index int) verifiable.JSONObject {
			return verifiable.SubjectToJSON(subj)
		})

		credMeta := CredentialMetadata{
			Format:         credType,
			Type:           credContents.Types,
			SubjectData:    subject,
			IssuanceDate:   credContents.Issued,
			ExpirationDate: credContents.Expired,
		}

		credMeta.Name = cred.CustomField(additionalClaimFieldName)
		credMeta.Description = cred.CustomField(additionalClaimFieldDesc)
		credMeta.AwardedDate = cred.CustomField(additionalClaimFieldAwardedDate)

		if credContents.Issuer != nil {
			credMeta.Issuer = verifiable.IssuerToJSON(*credContents.Issuer)
		}

		result[credContents.ID] = credMeta
	}

	if len(tx.ReceivedClaims.CustomScopeClaims) > 0 {
		result[customScopeProperty] = CredentialMetadata{
			CustomClaims: tx.ReceivedClaims.CustomScopeClaims,
		}
	}

	logger.Debugc(ctx, "RetrieveClaims succeed")

	err := s.sendOIDCInteractionEvent(ctx, spi.VerifierOIDCInteractionClaimsRetrieved, tx, profile, tx.ReceivedClaims)
	if err != nil {
		logger.Warnc(ctx, "Failed to send event", log.WithError(err))
	}

	return result
}

func (s *Service) DeleteClaims(_ context.Context, claimsID string) error {
	return s.transactionManager.DeleteReceivedClaims(claimsID)
}

func (s *Service) getDataIntegrityVerifier() (*dataintegrity.Verifier, error) {
	verifySuite := ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: s.documentLoader,
	})

	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: s.vdr,
	}, verifySuite)
	if err != nil {
		return nil, fmt.Errorf("new verifier: %w", err)
	}

	return verifier, nil
}

func (s *Service) extractClaimData(
	ctx context.Context,
	tx *Transaction,
	authResponse *AuthorizationResponseParsed,
	profile *profileapi.Verifier,
	verifiedPresentations map[string]*ProcessedVPToken,
) (*ReceivedClaims, error) {
	var presentations []*verifiable.Presentation

	for _, token := range authResponse.VPTokens {
		// TODO: think about better solution. If jwt is set, its wrap vp into sub object "vp" and this breaks Match
		token.Presentation.JWT = ""
		presentations = append(presentations, token.Presentation)
	}
	diVerifier, err := s.getDataIntegrityVerifier()
	if err != nil {
		return nil, resterr.NewSystemError(resterr.VerifierDataIntegrityVerifier, "create-verifier",
			fmt.Errorf("get data integrity verifier: %w", err))
	}

	opts := []presexch.MatchOption{
		presexch.WithCredentialOptions(
			verifiable.WithDataIntegrityVerifier(diVerifier),
			verifiable.WithExpectedDataIntegrityFields(crypto.AssertionMethod, "", ""),
			verifiable.WithJSONLDDocumentLoader(s.documentLoader),
			verifiable.WithProofChecker(defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(s.vdr)))),
		presexch.WithDisableSchemaValidation(),
	}

	if len(presentations) > 1 {
		opts = append(opts,
			presexch.WithMergedSubmissionMap(presentations[0].CustomFields[vpSubmissionProperty].(map[string]interface{})))
	}

	matchedCredentials, err := tx.PresentationDefinition.Match(presentations, s.documentLoader, opts...)
	if err != nil {
		return nil, resterr.NewCustomError(resterr.PresentationDefinitionMismatch,
			fmt.Errorf("presentation definition match: %w", err))
	}

	var storeCredentials []*verifiable.Credential

	for _, mc := range matchedCredentials {
		if profile.Checks != nil && profile.Checks.Presentation != nil && profile.Checks.Presentation.VCSubject {
			token, ok := verifiedPresentations[mc.PresentationID]
			if !ok {
				// this should never happen
				return nil, fmt.Errorf("missing verified presentation ID: %s", mc.PresentationID)
			}

			err = checkVCSubject(mc.Credential, token)
			if err != nil {
				return nil, fmt.Errorf("extractClaimData vc subject: %w", err)
			}

			logger.Debugc(ctx, "vc subject verified")
		}

		storeCredentials = append(storeCredentials, mc.Credential)
	}

	receivedClaims := &ReceivedClaims{
		CustomScopeClaims: authResponse.CustomScopeClaims,
		Credentials:       storeCredentials,
	}

	return receivedClaims, nil
}

func checkVCSubject(cred *verifiable.Credential, token *ProcessedVPToken) error {
	subjectID, err := verifiable.SubjectID(cred.Contents().Subject)
	if err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, "subject-id",
			fmt.Errorf("fail to parse credential as jwt: %w", err))
	}

	if cred.IsJWT() {
		// We use this strange code, because cred.JWTClaims(false) not take to account "sub" claim from jwt
		_, rawClaims, credErr := jwt.Parse(
			cred.JWTEnvelope.JWT,
			jwt.WithIgnoreClaimsMapDecoding(true),
		)
		if credErr != nil {
			return resterr.NewValidationError(resterr.InvalidValue, "jwt-envelope",
				fmt.Errorf("fail to parse credential as jwt: %w", err))
		}

		subjectID = fastjson.GetString(rawClaims, "sub")
	}

	if token.SignerDIDID != subjectID {
		return resterr.NewValidationError(resterr.InvalidValue, "subject-id",
			fmt.Errorf("vc subject(%s) does not match with vp signer(%s)",
				subjectID, token.SignerDIDID))
	}

	return nil
}

func (s *Service) createRequestObjectJWT(presentationDefinition *presexch.PresentationDefinition,
	tx *Transaction,
	nonce string,
	purpose string,
	customScopes []string,
	profile *profileapi.Verifier) (string, error) {
	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return "", resterr.NewSystemError(resterr.VerifierKMSRegistryComponent, "get-key-manaer",
			fmt.Errorf("initiate oidc interaction: get key manager failed: %w", err))
	}

	vpFormats := GetSupportedVPFormats(
		kms.SupportedKeyTypes(), profile.Checks.Presentation.Format, profile.Checks.Credential.Format)

	ro := s.createRequestObject(presentationDefinition, vpFormats, tx, nonce, purpose, customScopes, profile)

	signatureTypes := vcsverifiable.GetSignatureTypesByKeyTypeFormat(profile.OIDCConfig.KeyType, vcsverifiable.Jwt)
	if len(signatureTypes) < 1 {
		return "", resterr.NewValidationError(resterr.InvalidValue, "JWT.KeyType",
			fmt.Errorf("unsupported jwt key type %s", profile.OIDCConfig.KeyType))
	}

	vcsSigner, err := kms.NewVCSigner(profile.SigningDID.KMSKeyID, signatureTypes[0])
	if err != nil {
		return "", resterr.NewSystemError(resterr.VerifierVCSignerComponent, "create-signer",
			fmt.Errorf("initiate oidc interaction: get create signer failed: %w", err))
	}

	return signRequestObject(ro, profile, vcsSigner)
}

func signRequestObject(ro *RequestObject, profile *profileapi.Verifier, vcsSigner vc.SignerAlgorithm) (string, error) {
	signer := NewJWSSigner(profile.SigningDID.Creator, vcsSigner)

	token, err := jwt.NewJoseSigned(ro, nil, signer)
	if err != nil {
		return "", resterr.NewSystemError(resterr.VerifierVCSignerComponent, "sign-request",
			fmt.Errorf("initiate oidc interaction: sign token failed: %w", err))
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", resterr.NewSystemError(resterr.VerifierVCSignerComponent, "serialize-token",
			fmt.Errorf("initiate oidc interaction: serialize token failed: %w", err))
	}

	return tokenBytes, nil
}

func GetSupportedVPFormats(
	kmsSupportedKeyTypes []kmsapi.KeyType,
	supportedVPFormats,
	supportedVCFormats []vcsverifiable.Format,
) *presexch.Format {
	var jwtSignatureTypeNames []string // order here is important
	var ldpSignatureTypeNames []string

	for _, keyType := range kmsSupportedKeyTypes {
		for _, st := range vcsverifiable.GetSignatureTypesByKeyTypeFormat(keyType, vcsverifiable.Jwt) {
			name := st.Name()
			if lo.Contains(jwtSignatureTypeNames, name) {
				continue
			}

			jwtSignatureTypeNames = append(jwtSignatureTypeNames, name)
		}

		for _, st := range vcsverifiable.GetSignatureTypesByKeyTypeFormat(keyType, vcsverifiable.Ldp) {
			name := st.Name()
			if lo.Contains(ldpSignatureTypeNames, name) {
				continue
			}

			ldpSignatureTypeNames = append(ldpSignatureTypeNames, name)
		}
	}

	formats := &presexch.Format{}

	for _, vpFormat := range supportedVPFormats {
		switch vpFormat {
		case vcsverifiable.Jwt:
			formats.JwtVP = &presexch.JwtType{Alg: jwtSignatureTypeNames}
		case vcsverifiable.Ldp:
			formats.LdpVP = &presexch.LdpType{ProofType: ldpSignatureTypeNames}
		}
	}

	for _, vpFormat := range supportedVCFormats {
		switch vpFormat {
		case vcsverifiable.Jwt:
			formats.JwtVC = &presexch.JwtType{Alg: jwtSignatureTypeNames}
		case vcsverifiable.Ldp:
			formats.LdpVC = &presexch.LdpType{ProofType: ldpSignatureTypeNames}
		}
	}

	return formats
}

func (s *Service) createRequestObject(
	presentationDefinition *presexch.PresentationDefinition,
	vpFormats *presexch.Format,
	tx *Transaction,
	nonce string,
	purpose string,
	customScopes []string,
	profile *profileapi.Verifier) *RequestObject {
	tokenLifetime := s.tokenLifetime
	now := time.Now()
	return &RequestObject{
		JTI:          uuid.New().String(),
		IAT:          now.Unix(),
		ISS:          profile.SigningDID.DID,
		ResponseType: "id_token",
		ResponseMode: "post",
		Scope:        getScope(customScopes),
		Nonce:        nonce,
		ClientID:     profile.SigningDID.DID,
		RedirectURI:  s.redirectURL,
		State:        string(tx.ID),
		Exp:          now.Add(tokenLifetime).Unix(),
		Registration: RequestObjectRegistration{
			ClientName:                  profile.Name,
			SubjectSyntaxTypesSupported: []string{"did:ion"},
			VPFormats:                   vpFormats,
			ClientPurpose:               purpose,
			LogoURI:                     profile.LogoURL,
		},
		Claims: RequestObjectClaims{VPToken: VPToken{
			presentationDefinition,
		}},
	}
}

func (s *Service) sendOIDCInteractionEvent(
	ctx context.Context,
	eventType spi.EventType,
	tx *Transaction,
	profile *profileapi.Verifier,
	receivedClaims *ReceivedClaims,
) error {
	ep := createTxEventPayload(tx, profile)

	for _, c := range receivedClaims.Credentials {
		cred := c.Contents()

		subjectID, err := verifiable.SubjectID(cred.Subject)
		if err != nil {
			logger.Warnc(ctx, "Unable to extract ID from credential subject: %w", log.WithError(err))
		}

		var issuerID string
		if cred.Issuer != nil {
			issuerID = cred.Issuer.ID
		}

		ep.Credentials = append(ep.Credentials, &CredentialEventPayload{
			ID:        cred.ID,
			Types:     cred.Types,
			IssuerID:  issuerID,
			SubjectID: subjectID,
		})
	}

	event, err := CreateEvent(eventType, tx.ID, ep)
	if err != nil {
		return fmt.Errorf("create OIDC verifier event: %w", err)
	}

	err = s.eventSvc.Publish(ctx, s.eventTopic, event)
	if err != nil {
		return fmt.Errorf("send OIDC verifier event: %w", err)
	}

	return nil
}

func getScope(customScopes []string) string {
	scope := "openid"
	if len(customScopes) > 0 {
		scope += "+" + strings.Join(customScopes, "+")
	}

	return scope
}

type JWSSigner struct {
	keyID  string
	signer vc.SignerAlgorithm
}

func NewJWSSigner(keyID string, signer vc.SignerAlgorithm) *JWSSigner {
	return &JWSSigner{
		keyID:  keyID,
		signer: signer,
	}
}

// Sign signs.
func (s *JWSSigner) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

// Headers provides JWS headers. "alg" header must be provided (see https://tools.ietf.org/html/rfc7515#section-4.1)
func (s *JWSSigner) Headers() jose.Headers {
	return jose.Headers{
		jose.HeaderKeyID:     s.keyID,
		jose.HeaderAlgorithm: s.signer.Alg(),
	}
}

func CreateEvent(
	eventType spi.EventType,
	transactionID TxID,
	ep *EventPayload,
) (*spi.Event, error) {
	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	event := spi.NewEventWithPayload(uuid.NewString(), "source://vcs/verifier", eventType, payload)
	event.TransactionID = string(transactionID)

	return event, nil
}

func createTxEventPayload(tx *Transaction, profile *profileapi.Verifier) *EventPayload {
	var presentationDefID string

	if tx.PresentationDefinition != nil {
		presentationDefID = tx.PresentationDefinition.ID
	}

	return &EventPayload{
		WebHook:                  profile.WebHook,
		ProfileID:                profile.ID,
		ProfileVersion:           profile.Version,
		OrgID:                    profile.OrganizationID,
		PresentationDefinitionID: presentationDefID,
	}
}

func getFilter(def *presexch.PresentationDefinition) *Filter {
	if def == nil {
		return nil
	}

	return &Filter{Fields: getConstraintFields(def)}
}

func getConstraintFields(def *presexch.PresentationDefinition) []string {
	if def == nil {
		return nil
	}

	fieldsMap := make(map[string]struct{})

	for _, desc := range def.InputDescriptors {
		if desc.Constraints != nil {
			for _, f := range desc.Constraints.Fields {
				fieldsMap[f.ID] = struct{}{}
			}
		}
	}

	return lo.Keys(fieldsMap)
}
