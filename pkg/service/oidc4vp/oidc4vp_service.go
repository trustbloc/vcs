/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4vp_service_mocks_test.go -self_package mocks -package oidc4vp_test -source=oidc4vp_service.go -mock_names transactionManager=MockTransactionManager,events=MockEvents,kmsRegistry=MockKMSRegistry,requestObjectStore=MockRequestObjectStore,profileService=MockProfileService,presentationVerifier=MockPresentationVerifier,trustRegistry=MockTrustRegistry,attachmentService=MockAttachmentService

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
	"github.com/trustbloc/vc-go/dataintegrity/suite/eddsa2022"
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
	oidc4vperr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4vp"
	"github.com/trustbloc/vcs/pkg/service/trustregistry"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

var logger = log.New("oidc4vp-service")

const (
	vpSubmissionProperty       = "presentation_submission"
	customScopeProperty        = "_scope"
	vpTokenIDTokenResponseType = "vp_token id_token" //nolint:gosec
	directPostResponseMode     = "direct_post"
	didClientIDScheme          = "did"
	defaultURLScheme           = "openid-vc://"
)

const (
	additionalClaimFieldName        = "name"
	additionalClaimFieldDesc        = "description"
	additionalClaimFieldAwardedDate = "awardedDate"
)

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
	Delete(txID TxID) error
}

type requestObjectStore interface {
	Publish(ctx context.Context, requestObject string) (string, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Verifier, error)
}

type attachmentService interface {
	GetAttachments(
		ctx context.Context,
		subjects []verifiable.Subject,
		idTokenAttachments map[string]string,
	) ([]*Attachment, error)
}

type presentationVerifier interface {
	VerifyPresentation(
		ctx context.Context,
		presentation *verifiable.Presentation,
		opts *verifypresentation.Options,
		profile *profileapi.Verifier,
	) (
		verifypresentation.PresentationVerificationResult, map[string][]string, error,
	)
}

type trustRegistry interface {
	trustregistry.ValidatePresentation
}

type metricsProvider interface {
	VerifyOIDCVerifiablePresentationTime(value time.Duration)
}

type Config struct {
	TransactionManager   transactionManager
	RequestObjectStore   requestObjectStore
	KMSRegistry          kmsRegistry
	DocumentLoader       ld.DocumentLoader
	ProfileService       profileService
	EventSvc             eventService
	EventTopic           string
	PresentationVerifier presentationVerifier
	VDR                  vdrapi.Registry
	TrustRegistry        trustRegistry
	ResponseURI          string
	TokenLifetime        time.Duration
	Metrics              metricsProvider
	AttachmentService    attachmentService
}

type Service struct {
	eventSvc             eventService
	eventTopic           string
	transactionManager   transactionManager
	requestObjectStore   requestObjectStore
	kmsRegistry          kmsRegistry
	documentLoader       ld.DocumentLoader
	profileService       profileService
	presentationVerifier presentationVerifier
	vdr                  vdrapi.Registry
	trustRegistry        trustRegistry
	attachmentService    attachmentService

	responseURI   string
	tokenLifetime time.Duration

	metrics metricsProvider
}

func NewService(cfg *Config) *Service {
	metrics := cfg.Metrics

	if metrics == nil {
		metrics = &noopMetricsProvider.NoMetrics{}
	}

	return &Service{
		eventSvc:             cfg.EventSvc,
		eventTopic:           cfg.EventTopic,
		transactionManager:   cfg.TransactionManager,
		requestObjectStore:   cfg.RequestObjectStore,
		kmsRegistry:          cfg.KMSRegistry,
		documentLoader:       cfg.DocumentLoader,
		profileService:       cfg.ProfileService,
		presentationVerifier: cfg.PresentationVerifier,
		responseURI:          cfg.ResponseURI,
		tokenLifetime:        cfg.TokenLifetime,
		vdr:                  cfg.VDR,
		trustRegistry:        cfg.TrustRegistry,
		metrics:              metrics,
		attachmentService:    cfg.AttachmentService,
	}
}

func (s *Service) sendTxEvent(
	ctx context.Context,
	eventType spi.EventType,
	tx *Transaction,
	profile *profileapi.Verifier,
) error {
	event, err := CreateEvent(eventType, tx.ID, createBaseTxEventPayload(tx, profile))
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
	ep := createBaseTxEventPayload(tx, profile)
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
	var oidc4vpErr *oidc4vperr.Error

	ep := createBaseTxEventPayload(tx, profile)

	if errors.As(e, &oidc4vpErr) {
		ep.Error = oidc4vpErr.Error()
		ep.ErrorCode = oidc4vpErr.Code()
		ep.ErrorComponent = oidc4vpErr.Component()
	} else {
		ep.Error = e.Error()
	}

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
	customURLScheme string,
	profile *profileapi.Verifier,
) (*InteractionInfo, error) { // *oidc4vp.Error
	logger.Debugc(ctx, "InitiateOidcInteraction begin")

	if profile.SigningDID == nil {
		return nil, oidc4vperr.
			NewBadRequestError(errors.New("profile signing did can't be nil")).
			WithIncorrectValue("profile.SigningDID")
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
		return nil, oidc4vperr.
			NewBadRequestError(err).
			WithIncorrectValue("profile.SigningDID").
			WithComponent(resterr.VerifierTxnMgrComponent).
			WithOperation("create-txn").
			WithErrorPrefix("fail to create oidc tx")
	}

	logger.Debugc(ctx, "InitiateOidcInteraction tx created", log.WithTxID(string(tx.ID)))

	token, createReqObjErr := s.createRequestObjectJWT(presentationDefinition, tx, nonce, purpose, customScopes, profile)
	if createReqObjErr != nil {
		s.sendFailedTransactionEvent(ctx, tx, profile, createReqObjErr)

		return nil, createReqObjErr
	}

	logger.Debugc(ctx, "InitiateOidcInteraction request object created")

	requestURI, err := s.requestObjectStore.Publish(ctx, token)
	if err != nil {
		oidc4vpErr := oidc4vperr.
			NewBadRequestError(err).
			WithComponent(resterr.TransactionStoreComponent).
			WithErrorPrefix("publish request object")

		s.sendFailedTransactionEvent(ctx, tx, profile, oidc4vpErr)

		return nil, oidc4vpErr
	}

	logger.Debugc(ctx, "InitiateOidcInteraction request object published")

	urlScheme := defaultURLScheme

	if customURLScheme != "" {
		urlScheme = customURLScheme
	}

	authorizationRequest := fmt.Sprintf("%s?request_uri=%s", urlScheme, requestURI)

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
) (map[string]*ProcessedVPToken, *oidc4vperr.Error) {
	verifiedPresentations := make(map[string]*ProcessedVPToken)

	var validationErrors []*oidc4vperr.Error
	mut := sync.Mutex{}
	wg := sync.WaitGroup{}
	for _, token2 := range tokens {
		token := token2
		wg.Add(1)

		go func() {
			defer wg.Done()
			if !lo.Contains(profile.Checks.Presentation.Format, token.VpTokenFormat) {
				e := oidc4vperr.
					NewBadRequestError(fmt.Errorf("profile does not support %s vp_token format", token.VpTokenFormat)).
					WithIncorrectValue("format")

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
				e := oidc4vperr.
					NewBadRequestError(innerErr).
					WithOperation("verify-presentation").
					WithComponent(resterr.VerifierPresentationVerifierComponent).
					WithErrorPrefix("presentation verification failed")

				mut.Lock()
				validationErrors = append(validationErrors, e)
				mut.Unlock()
				return
			}

			if len(vr.Errors()) > 0 {
				e := oidc4vperr.
					NewBadRequestError(vr.Errors()[0].Error).
					WithComponent(resterr.VerifierPresentationVerifierComponent).
					WithOperation("verify-presentation").
					WithErrorPrefix("presentation verification checks failed")

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
				e := oidc4vperr.
					NewBadRequestError(fmt.Errorf("duplicate presentation ID: %s", token.Presentation.ID))

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
) error { // *oidc4vp.Error
	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation begin")
	startTime := time.Now()

	defer func() {
		logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation", log.WithDuration(time.Since(startTime)))
	}()

	if len(authResponse.VPTokens) == 0 {
		// this should never happen
		return oidc4vperr.
			NewBadRequestError(fmt.Errorf("must have at least one token")).
			WithIncorrectValue("tokens")
	}

	// All tokens have same nonce
	tx, validNonce, err := s.transactionManager.GetByOneTimeToken(authResponse.VPTokens[0].Nonce)
	if err != nil {
		return oidc4vperr.
			NewBadRequestError(err).
			WithOperation("get-by-one-time-token").
			WithComponent(resterr.VerifierTxnMgrComponent).
			WithErrorPrefix("get tx by nonce failed")
	}

	if !validNonce || tx.ID != txID {
		return oidc4vperr.
			NewBadRequestError(fmt.Errorf("invalid nonce")).
			WithIncorrectValue("nonce")
	}

	// If amount custom scopes is not equal to amount of supplied claims.
	unexpectedClaimsAmount := len(tx.CustomScopes) != len(authResponse.CustomScopeClaims)
	// If no additional claims supplied for any of custom scopes.
	_, noAdditionalClaimsSupplied := lo.Find(tx.CustomScopes, func(item string) bool {
		val, ok := authResponse.CustomScopeClaims[item]

		return !ok || len(val) == 0
	})

	if unexpectedClaimsAmount || noAdditionalClaimsSupplied {
		return oidc4vperr.
			NewBadRequestError(fmt.Errorf("invalid _scope")).
			WithIncorrectValue("_scope")
	}

	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation nonce verified")

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		return oidc4vperr.NewBadRequestError(err).WithErrorPrefix("getProfile")
	}

	if err = s.sendTxEvent(ctx, spi.VerifierOIDCInteractionQRScanned, tx, profile); err != nil {
		return oidc4vperr.NewBadRequestError(err).WithErrorPrefix("send event")
	}

	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation profile fetched", logfields.WithProfileID(profile.ID))

	policyChan := make(chan error)
	go func() {
		defer close(policyChan)
		policyChan <- s.checkPolicy(ctx, profile, authResponse.AttestationVP, authResponse.VPTokens)
	}()

	logger.Debugc(ctx, fmt.Sprintf("VerifyOIDCVerifiablePresentation count of tokens is %v", len(authResponse.VPTokens)))

	verifiedPresentations, oidc4vpErr := s.verifyTokens(ctx, tx, profile, authResponse.VPTokens)
	if oidc4vpErr != nil {
		return oidc4vpErr.WithErrorPrefix("verify tokens")
	}

	if policyErr := <-policyChan; policyErr != nil {
		return oidc4vperr.NewBadRequestError(policyErr)
	}

	receivedClaims, oidc4vpErr := s.extractClaimData(ctx, tx, authResponse, profile, verifiedPresentations)
	if oidc4vpErr != nil {
		s.sendFailedTransactionEvent(ctx, tx, profile, oidc4vpErr)

		return oidc4vpErr.WithErrorPrefix("extract claim data")
	}

	err = s.transactionManager.StoreReceivedClaims(
		tx.ID,
		receivedClaims,
		profile.DataConfig.OIDC4VPTransactionDataTTL,
		profile.DataConfig.OIDC4VPReceivedClaimsDataTTL,
	)
	if err != nil {
		oidc4vpErr = oidc4vperr.NewBadRequestError(err).
			WithComponent(resterr.VerifierTxnMgrComponent).
			WithOperation("store-received-claims").
			WithErrorPrefix("store received claims")

		s.sendFailedTransactionEvent(ctx, tx, profile, oidc4vpErr)

		return oidc4vpErr
	}

	logger.Debugc(ctx, "extractClaimData claims stored")

	err = s.sendOIDCInteractionEvent(
		ctx, spi.VerifierOIDCInteractionSucceeded, tx, profile, receivedClaims, authResponse.InteractionDetails)
	if err != nil {
		return oidc4vperr.NewBadRequestError(err)
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
		subject := lo.Map(credContents.Subject, func(subj verifiable.Subject, _ int) verifiable.JSONObject {
			return verifiable.SubjectToJSON(subj)
		})

		credMeta := CredentialMetadata{
			Format:      credType,
			Type:        credContents.Types,
			SubjectData: subject,
		}

		if verifiable.IsBaseContext(credContents.Context, verifiable.V2ContextURI) {
			credMeta.ValidFrom = credContents.Issued
			credMeta.ValidUntil = credContents.Expired
		} else {
			credMeta.IssuanceDate = credContents.Issued
			credMeta.ExpirationDate = credContents.Expired
		}

		credMeta.Name = cred.CustomField(additionalClaimFieldName)
		credMeta.Description = cred.CustomField(additionalClaimFieldDesc)
		credMeta.AwardedDate = cred.CustomField(additionalClaimFieldAwardedDate)

		if credContents.Issuer != nil {
			credMeta.Issuer = verifiable.IssuerToJSON(*credContents.Issuer)
		}

		if s.attachmentService != nil {
			att, attErr := s.attachmentService.GetAttachments(
				ctx,
				credContents.Subject,
				tx.ReceivedClaims.Attachments,
			)
			if attErr != nil {
				logger.Errorc(ctx, fmt.Sprintf("Failed to get attachments: %+v", attErr))
			}

			credMeta.Attachments = att
		}

		result[credContents.ID] = credMeta
	}

	if len(tx.ReceivedClaims.CustomScopeClaims) > 0 {
		result[customScopeProperty] = CredentialMetadata{
			CustomClaims: tx.ReceivedClaims.CustomScopeClaims,
		}
	}

	logger.Debugc(ctx, "RetrieveClaims succeed")

	err := s.sendOIDCInteractionEvent(ctx, spi.VerifierOIDCInteractionClaimsRetrieved, tx, profile, tx.ReceivedClaims, nil)
	if err != nil {
		logger.Warnc(ctx, "Failed to send event", log.WithError(err))
	}

	return result
}

func (s *Service) DeleteClaims(_ context.Context, claimsID string) error {
	return s.transactionManager.DeleteReceivedClaims(claimsID)
}

func (s *Service) getDataIntegrityVerifier() (*dataintegrity.Verifier, error) {
	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: s.vdr,
	}, eddsa2022.NewVerifierInitializer(&eddsa2022.VerifierInitializerOptions{
		LDDocumentLoader: s.documentLoader,
	}), ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: s.documentLoader,
	}))
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
) (*ReceivedClaims, *oidc4vperr.Error) {
	var presentations []*verifiable.Presentation

	for _, token := range authResponse.VPTokens {
		presentations = append(presentations, token.Presentation)
	}

	dataIntegrityVerifier, err := s.getDataIntegrityVerifier()
	if err != nil {
		return nil, oidc4vperr.NewBadRequestError(err).
			WithOperation("create-verifier").
			WithErrorPrefix("get data integrity verifier")
	}

	opts := []presexch.MatchOption{
		presexch.WithCredentialOptions(
			verifiable.WithDataIntegrityVerifier(dataIntegrityVerifier),
			verifiable.WithExpectedDataIntegrityFields(crypto.AssertionMethod, "", ""),
			verifiable.WithJSONLDDocumentLoader(s.documentLoader),
			verifiable.WithProofChecker(defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(s.vdr))),
		),
		presexch.WithDisableSchemaValidation(),
	}

	if len(presentations) > 1 {
		opts = append(opts,
			presexch.WithMergedSubmissionMap(
				presentations[0].CustomFields[vpSubmissionProperty].(map[string]interface{})), // nolint
		)
	}

	matchedCredentials, err := tx.PresentationDefinition.Match(presentations, s.documentLoader, opts...)
	if err != nil {
		return nil, oidc4vperr.NewBadRequestError(err).
			WithComponent(resterr.VerifierPresentationVerifierComponent).
			WithErrorPrefix("presentation definition match")
	}

	var storeCredentials []*verifiable.Credential

	for _, mc := range matchedCredentials {
		if profile.Checks != nil && profile.Checks.Presentation != nil && profile.Checks.Presentation.VCSubject {
			token, ok := verifiedPresentations[mc.PresentationID]
			if !ok {
				// this should never happen
				return nil, oidc4vperr.
					NewBadRequestError(fmt.Errorf("missing verified presentation ID: %s", mc.PresentationID))
			}

			oidc4vpErr := checkVCSubject(mc.Credential, token)
			if oidc4vpErr != nil {
				return nil, oidc4vpErr.WithErrorPrefix("extractClaimData vc subject")
			}

			logger.Debugc(ctx, "vc subject verified")
		}

		storeCredentials = append(storeCredentials, mc.Credential)
	}

	receivedClaims := &ReceivedClaims{
		CustomScopeClaims: authResponse.CustomScopeClaims,
		Attachments:       authResponse.Attachments,
		Credentials:       storeCredentials,
	}

	return receivedClaims, nil
}

func checkVCSubject(cred *verifiable.Credential, token *ProcessedVPToken) *oidc4vperr.Error {
	subjectID, err := verifiable.SubjectID(cred.Contents().Subject)
	if err != nil {
		return oidc4vperr.NewBadRequestError(err).
			WithIncorrectValue("subject-id").
			WithErrorPrefix("fail to parse credential as jwt")
	}

	if cred.IsJWT() {
		// We use this strange code, because cred.JWTClaims(false) not take to account "sub" claim from jwt
		_, rawClaims, credErr := jwt.Parse(
			cred.JWTEnvelope.JWT,
			jwt.WithIgnoreClaimsMapDecoding(true),
		)
		if credErr != nil {
			return oidc4vperr.NewBadRequestError(err).
				WithIncorrectValue("jwt-envelope").
				WithErrorPrefix("fail to parse credential as jwt")
		}

		subjectID = fastjson.GetString(rawClaims, "sub")
	}

	if token.SignerDIDID != subjectID {
		return oidc4vperr.
			NewBadRequestError(fmt.Errorf("vc subject(%s) does not match with vp signer(%s)",
				subjectID, token.SignerDIDID)).
			WithIncorrectValue("subject-id").
			WithErrorPrefix("fail to parse credential as jwt")
	}

	return nil
}

func (s *Service) createRequestObjectJWT(
	presentationDefinition *presexch.PresentationDefinition,
	tx *Transaction,
	nonce string,
	purpose string,
	customScopes []string,
	profile *profileapi.Verifier) (string, *oidc4vperr.Error) {
	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return "", oidc4vperr.NewBadRequestError(err).
			WithComponent(resterr.VerifierKMSRegistryComponent).
			WithOperation("get-key-manaer").
			WithErrorPrefix("initiate oidc interaction: get key manager failed")
	}

	vpFormats := GetSupportedVPFormats(
		kms.SupportedKeyTypes(), profile.Checks.Presentation.Format, profile.Checks.Credential.Format)

	ro := s.createRequestObject(presentationDefinition, vpFormats, tx, nonce, purpose, customScopes, profile)

	signatureTypes := vcsverifiable.GetSignatureTypesByKeyTypeFormat(profile.OIDCConfig.KeyType, vcsverifiable.Jwt)
	if len(signatureTypes) < 1 {
		return "", oidc4vperr.
			NewBadRequestError(fmt.Errorf("unsupported jwt key type %s", profile.OIDCConfig.KeyType)).
			WithComponent(resterr.VerifierOIDC4vpSvcComponent).
			WithIncorrectValue("JWT.KeyType")
	}

	vcsSigner, err := kms.NewVCSigner(profile.SigningDID.KMSKeyID, signatureTypes[0])
	if err != nil {
		return "", oidc4vperr.NewBadRequestError(err).
			WithComponent(resterr.VerifierVCSignerComponent).
			WithOperation("create-signer").
			WithErrorPrefix("initiate oidc interaction: get create signer failed")
	}

	return signRequestObject(ro, profile, vcsSigner)
}

func signRequestObject(
	ro *RequestObject, profile *profileapi.Verifier, vcsSigner vc.SignerAlgorithm) (string, *oidc4vperr.Error) {
	signer := NewJWSSigner(profile.SigningDID.Creator, vcsSigner)

	token, err := jwt.NewJoseSigned(ro, nil, signer)
	if err != nil {
		return "", oidc4vperr.NewBadRequestError(err).
			WithComponent(resterr.VerifierVCSignerComponent).
			WithOperation("sign-request").
			WithErrorPrefix("initiate oidc interaction: sign token failed")
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", oidc4vperr.NewBadRequestError(err).
			WithComponent(resterr.VerifierVCSignerComponent).
			WithOperation("serialize-token").
			WithErrorPrefix("initiate oidc interaction: serialize token failed")
	}

	return tokenBytes, nil
}

func GetSupportedVPFormats(
	kmsSupportedKeyTypes []kmsapi.KeyType,
	supportedVPFormats,
	supportedVCFormats []vcsverifiable.Format,
) *presexch.Format {
	supportedFormats := map[vcsverifiable.Format][]string{ // order here is important
		vcsverifiable.Jwt: {},
		vcsverifiable.Cwt: {},
		vcsverifiable.Ldp: {},
	}

	for _, format := range supportedVPFormats {
		for _, keyType := range kmsSupportedKeyTypes {
			for _, st := range vcsverifiable.GetSignatureTypesByKeyTypeFormat(keyType, format) {
				name := st.Name()
				if lo.Contains(supportedFormats[format], name) {
					continue
				}

				supportedFormats[format] = append(supportedFormats[format], name)
			}
		}
	}

	formats := &presexch.Format{}

	for _, vpFormat := range supportedVPFormats {
		switch vpFormat {
		case vcsverifiable.Jwt:
			formats.JwtVP = &presexch.JwtType{Alg: supportedFormats[vcsverifiable.Jwt]}
		case vcsverifiable.Ldp:
			formats.LdpVP = &presexch.LdpType{ProofType: supportedFormats[vcsverifiable.Ldp]}
		case vcsverifiable.Cwt:
			formats.CwtVP = &presexch.CwtType{Alg: supportedFormats[vcsverifiable.Cwt]}
		}
	}

	for _, vpFormat := range supportedVCFormats {
		switch vpFormat {
		case vcsverifiable.Jwt:
			formats.JwtVC = &presexch.JwtType{Alg: supportedFormats[vcsverifiable.Jwt]}
		case vcsverifiable.Ldp:
			formats.LdpVC = &presexch.LdpType{ProofType: supportedFormats[vcsverifiable.Ldp]}
		case vcsverifiable.Cwt:
			formats.LdpVC = &presexch.LdpType{ProofType: supportedFormats[vcsverifiable.Cwt]}
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
		JTI:            uuid.New().String(),
		IAT:            now.Unix(),
		ISS:            profile.SigningDID.DID,
		ResponseType:   vpTokenIDTokenResponseType,
		ResponseMode:   directPostResponseMode,
		ResponseURI:    s.responseURI,
		Scope:          getScope(customScopes),
		Nonce:          nonce,
		ClientID:       profile.SigningDID.DID,
		ClientIDScheme: didClientIDScheme,
		RedirectURI:    s.responseURI,
		State:          string(tx.ID),
		Exp:            now.Add(tokenLifetime).Unix(),
		ClientMetadata: &ClientMetadata{
			ClientName:                  profile.Name,
			SubjectSyntaxTypesSupported: []string{"did:web", "did:jwk", "did:key", "did:ion"},
			VPFormats:                   vpFormats,
			ClientPurpose:               purpose,
			LogoURI:                     profile.LogoURL,
		},
		PresentationDefinition: presentationDefinition,
	}
}

func (s *Service) sendOIDCInteractionEvent(
	ctx context.Context,
	eventType spi.EventType,
	tx *Transaction,
	profile *profileapi.Verifier,
	receivedClaims *ReceivedClaims,
	interactionDetails map[string]interface{},
) error {
	ep := createBaseTxEventPayload(tx, profile)

	ep.InteractionDetails = interactionDetails

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

func createBaseTxEventPayload(tx *Transaction, profile *profileapi.Verifier) *EventPayload {
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
