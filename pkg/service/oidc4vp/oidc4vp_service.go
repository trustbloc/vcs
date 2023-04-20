/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4vp_service_mocks_test.go -self_package mocks -package oidc4vp_test -source=oidc4vp_service.go -mock_names transactionManager=MockTransactionManager,events=MockEvents,kmsRegistry=MockKMSRegistry,requestObjectPublicStore=MockRequestObjectPublicStore,profileService=MockProfileService,presentationVerifier=MockPresentationVerifier

package oidc4vp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	noopMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/noop"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

var logger = log.New("oidc4vp-service")

const vpSubmissionProperty = "presentation_submission"

var ErrDataNotFound = errors.New("data not found")

type eventService interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type transactionManager interface {
	CreateTx(pd *presexch.PresentationDefinition, profileID string) (*Transaction, string, error)
	StoreReceivedClaims(txID TxID, claims *ReceivedClaims) error
	DeleteReceivedClaims(claimsID string) error
	GetByOneTimeToken(nonce string) (*Transaction, bool, error)
	Get(txID TxID) (*Transaction, error)
}

type requestObjectPublicStore interface {
	Publish(ctx context.Context, requestObject string, accessRequestObjectEvent *spi.Event) (string, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Verifier, error)
}

type presentationVerifier interface {
	VerifyPresentation(
		ctx context.Context,
		presentation *verifiable.Presentation,
		opts *verifypresentation.Options,
		profile *profileapi.Verifier) ([]verifypresentation.PresentationVerificationCheckResult, error)
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
	PublicKeyFetcher         verifiable.PublicKeyFetcher

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
	publicKeyFetcher         verifiable.PublicKeyFetcher

	redirectURL   string
	tokenLifetime time.Duration

	metrics metricsProvider
}

type RequestObjectRegistration struct {
	ClientName                  string           `json:"client_name"`
	SubjectSyntaxTypesSupported []string         `json:"subject_syntax_types_supported"`
	VPFormats                   *presexch.Format `json:"vp_formats"`
	ClientPurpose               string           `json:"client_purpose"`
}

type eventPayload struct {
	WebHook   string `json:"webHook,omitempty"`
	ProfileID string `json:"profileID,omitempty"`
	OrgID     string `json:"orgID,omitempty"`
	Error     string `json:"error,omitempty"`
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
		publicKeyFetcher:         cfg.PublicKeyFetcher,
		metrics:                  metrics,
	}
}

func (s *Service) createEvent(tx *Transaction, profile *profileapi.Verifier,
	eventType spi.EventType, e error) (*spi.Event, error) {
	ep := eventPayload{
		WebHook:   profile.WebHook,
		ProfileID: profile.ID,
		OrgID:     profile.OrganizationID,
	}

	if e != nil {
		ep.Error = e.Error()
	}

	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	event := spi.NewEventWithPayload(uuid.NewString(), profile.URL, eventType, payload)
	event.TransactionID = string(tx.ID)

	return event, nil
}

func (s *Service) sendEvent(ctx context.Context, tx *Transaction, profile *profileapi.Verifier,
	eventType spi.EventType) error {
	return s.sendEventWithError(ctx, tx, profile, eventType, nil)
}

func (s *Service) sendEventWithError(ctx context.Context, tx *Transaction, profile *profileapi.Verifier,
	eventType spi.EventType, e error) error {
	event, err := s.createEvent(tx, profile, eventType, e)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
}

func (s *Service) sendFailedEvent(ctx context.Context, tx *Transaction, profile *profileapi.Verifier, err error) {
	e := s.sendEventWithError(ctx, tx, profile, spi.VerifierOIDCInteractionFailed, err)
	logger.Debug("sending Failed OIDC verifier event error, ignoring..", log.WithError(e))
}

func (s *Service) InitiateOidcInteraction(
	ctx context.Context,
	presentationDefinition *presexch.PresentationDefinition,
	purpose string,
	profile *profileapi.Verifier,
) (*InteractionInfo, error) {
	logger.Debug("InitiateOidcInteraction begin")

	if profile.SigningDID == nil {
		return nil, errors.New("profile signing did can't be nil")
	}

	tx, nonce, err := s.transactionManager.CreateTx(presentationDefinition, profile.ID)
	if err != nil {
		return nil, fmt.Errorf("fail to create oidc tx: %w", err)
	}

	logger.Debug("InitiateOidcInteraction tx created", log.WithTxID(string(tx.ID)))

	if errSendEvent := s.sendEvent(ctx, tx, profile, spi.VerifierOIDCInteractionInitiated); errSendEvent != nil {
		return nil, errSendEvent
	}

	token, err := s.createRequestObjectJWT(presentationDefinition, tx, nonce, purpose, profile)
	if err != nil {
		return nil, err
	}

	logger.Debug("InitiateOidcInteraction request object created")

	accessRequestObjectEvent, err := s.createEvent(tx, profile, spi.VerifierOIDCInteractionQRScanned, nil)
	if err != nil {
		return nil, err
	}

	requestURI, err := s.requestObjectPublicStore.Publish(ctx, token, accessRequestObjectEvent)
	if err != nil {
		return nil, fmt.Errorf("fail publish request object: %w", err)
	}

	logger.Debug("InitiateOidcInteraction request object published")

	logger.Debug("InitiateOidcInteraction succeed")

	return &InteractionInfo{
		AuthorizationRequest: "openid-vc://?request_uri=" + requestURI,
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
			// TODO: should domain and challenge be verified?
			vr, innerErr := s.presentationVerifier.VerifyPresentation(ctx, token.Presentation, nil, profile)
			if innerErr != nil {
				e := fmt.Errorf("presentation verification failed: %w", innerErr)
				s.sendFailedEvent(ctx, tx, profile, e)

				mut.Lock()
				validationErrors = append(validationErrors, e)
				mut.Unlock()
				return
			}

			if len(vr) > 0 {
				e := fmt.Errorf("presentation verification checks failed: %s", vr[0].Error)
				s.sendFailedEvent(ctx, tx, profile, e)

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
				e := fmt.Errorf("duplicate presentation ID: %s", token.Presentation.ID)
				s.sendFailedEvent(ctx, tx, profile, e)

				validationErrors = append(validationErrors, e)
				return
			}
		}()
		logger.Debug(" VerifyOIDCVerifiablePresentation verified")
	}
	wg.Wait()

	if len(validationErrors) > 0 {
		return nil, validationErrors[0]
	}

	return verifiedPresentations, nil
}

func (s *Service) VerifyOIDCVerifiablePresentation(ctx context.Context, txID TxID, tokens []*ProcessedVPToken) error {
	logger.Debug("VerifyOIDCVerifiablePresentation begin")
	startTime := time.Now()

	defer func() {
		logger.Debug("VerifyOIDCVerifiablePresentation", log.WithDuration(time.Since(startTime)))
	}()

	if len(tokens) == 0 {
		// this should never happen
		return fmt.Errorf("must have at least one token")
	}

	// All tokens have same nonce
	tx, validNonce, err := s.transactionManager.GetByOneTimeToken(tokens[0].Nonce)
	if err != nil {
		return fmt.Errorf("get tx by nonce failed: %w", err)
	}

	if !validNonce || tx.ID != txID {
		return fmt.Errorf("invalid nonce")
	}

	logger.Debug("VerifyOIDCVerifiablePresentation nonce verified")

	profile, err := s.profileService.GetProfile(tx.ProfileID)
	if err != nil {
		return fmt.Errorf("inconsistent transaction state %w", err)
	}

	logger.Debug("VerifyOIDCVerifiablePresentation profile fetched", logfields.WithProfileID(profile.ID))

	logger.Debug(fmt.Sprintf("VerifyOIDCVerifiablePresentation count of tokens is %v", len(tokens)))

	verifiedPresentations, err := s.verifyTokens(ctx, tx, profile, tokens)
	if err != nil {
		return err
	}

	err = s.extractClaimData(tx, tokens, profile, verifiedPresentations)
	if err != nil {
		s.sendFailedEvent(ctx, tx, profile, err)

		return err
	}

	logger.Debug("extractClaimData claims stored")

	if err = s.sendEvent(ctx, tx, profile, spi.VerifierOIDCInteractionSucceeded); err != nil {
		return err
	}

	logger.Debug("VerifyOIDCVerifiablePresentation succeed")
	return nil
}

func (s *Service) GetTx(ctx context.Context, id TxID) (*Transaction, error) {
	return s.transactionManager.Get(id)
}

func (s *Service) RetrieveClaims(ctx context.Context, tx *Transaction) map[string]CredentialMetadata {
	logger.Debug("RetrieveClaims begin")
	result := map[string]CredentialMetadata{}

	for _, cred := range tx.ReceivedClaims.Credentials {
		credType := vcsverifiable.Ldp
		if cred.JWT != "" {
			credType = vcsverifiable.Jwt
		}

		var err error
		// Creating display credential.
		// For regular credentials (JWT and JSON-LD) this func will do nothing,
		// but for SD-JWT case it returns verifiable.Credential with disclosed subject claims.
		cred, err = cred.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
		if err != nil {
			logger.Debug("RetrieveClaims - failed to CreateDisplayCredential", log.WithError(err))
			continue
		}

		result[cred.ID] = CredentialMetadata{
			Format:         credType,
			Type:           cred.Types,
			SubjectData:    cred.Subject,
			Issuer:         cred.Issuer,
			IssuanceDate:   cred.Issued,
			ExpirationDate: cred.Expired,
		}
	}
	logger.Debug("RetrieveClaims succeed")

	return result
}

func (s *Service) DeleteClaims(ctx context.Context, claimsID string) error {
	return s.transactionManager.DeleteReceivedClaims(claimsID)
}

func (s *Service) extractClaimData(tx *Transaction, tokens []*ProcessedVPToken,
	profile *profileapi.Verifier, verifiedPresentations map[string]*ProcessedVPToken) error {
	var presentations []*verifiable.Presentation

	for _, token := range tokens {
		// TODO: think about better solution. If jwt is set, its wrap vp into sub object "vp" and this breaks Match
		token.Presentation.JWT = ""
		presentations = append(presentations, token.Presentation)
	}

	opts := []presexch.MatchOption{
		presexch.WithCredentialOptions(
			verifiable.WithJSONLDDocumentLoader(s.documentLoader),
			verifiable.WithPublicKeyFetcher(s.publicKeyFetcher)),
		presexch.WithDisableSchemaValidation(),
	}

	if len(presentations) > 1 {
		opts = append(opts,
			presexch.WithMergedSubmissionMap(presentations[0].CustomFields[vpSubmissionProperty].(map[string]interface{})))
	}

	matchedCredentials, err := tx.PresentationDefinition.Match(presentations, s.documentLoader, opts...)
	if err != nil {
		return fmt.Errorf("presentation definition match: %w", err)
	}

	storeCredentials := make(map[string]*verifiable.Credential)

	for inputDescID, mc := range matchedCredentials {
		if profile.Checks != nil && profile.Checks.Presentation != nil && profile.Checks.Presentation.VCSubject {
			token, ok := verifiedPresentations[mc.PresentationID]
			if !ok {
				// this should never happen
				return fmt.Errorf("missing verified presentation ID: %s", mc.PresentationID)
			}

			err = checkVCSubject(mc.Credential, token)
			if err != nil {
				return fmt.Errorf("extractClaimData vc subject: %w", err)
			}

			logger.Debug("vc subject verified")
		}

		storeCredentials[inputDescID] = mc.Credential
	}

	err = s.transactionManager.StoreReceivedClaims(tx.ID, &ReceivedClaims{Credentials: storeCredentials})
	if err != nil {
		return fmt.Errorf("store received claims: %w", err)
	}

	return nil
}

func checkVCSubject(cred *verifiable.Credential, token *ProcessedVPToken) error {
	subjectID, err := verifiable.SubjectID(cred.Subject)
	if err != nil {
		return fmt.Errorf("fail to parse credential as jwt: %w", err)
	}

	if cred.JWT != "" {
		// We use this strange code, because cred.JWTClaims(false) not take to account "sub" claim from jwt
		credToken, credErr := jwt.Parse(cred.JWT, jwt.WithSignatureVerifier(&noVerifier{}))
		if credErr != nil {
			return fmt.Errorf("fail to parse credential as jwt: %w", credErr)
		}

		subjectID = fmt.Sprint(credToken.Payload["sub"])
	}

	if token.Signer != subjectID {
		return fmt.Errorf("vc subject(%s) does not match with vp signer(%s)",
			subjectID, token.Signer)
	}

	return nil
}

func (s *Service) createRequestObjectJWT(presentationDefinition *presexch.PresentationDefinition,
	tx *Transaction,
	nonce string,
	purpose string,
	profile *profileapi.Verifier) (string, error) {
	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: get key manager failed: %w", err)
	}

	vpFormats := getSupportedVPFormats(kms)

	ro := s.createRequestObject(presentationDefinition, vpFormats, tx, nonce, purpose, profile)

	signingAlgorithm, err := vcsverifiable.GetJWTSignatureTypeByKey(profile.OIDCConfig.KeyType)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: get jwt signature type failed: %w", err)
	}

	vcsSigner, err := kms.NewVCSigner(profile.SigningDID.KMSKeyID, signingAlgorithm)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: get create signer failed: %w", err)
	}

	return singRequestObject(ro, profile, vcsSigner)
}

func singRequestObject(ro *RequestObject, profile *profileapi.Verifier, vcsSigner vc.SignerAlgorithm) (string, error) {
	signer := NewJWSSigner(profile.SigningDID.Creator, vcsSigner)

	token, err := jwt.NewSigned(ro, nil, signer)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: sign token failed: %w", err)
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: serialize token failed: %w", err)
	}

	return tokenBytes, nil
}

func getSupportedVPFormats(kms vcskms.VCSKeyManager) *presexch.Format {
	var signatureTypes []vcsverifiable.SignatureType

	for _, keyType := range kms.SupportedKeyTypes() {
		signatureTypes = append(signatureTypes, vcsverifiable.SignatureTypesSupportedKeyType(keyType)...)
	}

	var signatureTypesNames []string
	for _, signature := range signatureTypes {
		signatureTypesNames = append(signatureTypesNames, signature.Name())
	}

	return &presexch.Format{
		JwtVC: &presexch.JwtType{Alg: signatureTypesNames},
		JwtVP: &presexch.JwtType{Alg: signatureTypesNames},
	}
}

func (s *Service) createRequestObject(
	presentationDefinition *presexch.PresentationDefinition,
	vpFormats *presexch.Format,
	tx *Transaction,
	nonce string,
	purpose string,
	profile *profileapi.Verifier) *RequestObject {
	tokenLifetime := s.tokenLifetime
	now := time.Now()
	return &RequestObject{
		JTI:          uuid.New().String(),
		IAT:          now.Unix(),
		ISS:          profile.SigningDID.DID,
		ResponseType: "id_token",
		ResponseMode: "post",
		Scope:        "openid",
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
		},
		Claims: RequestObjectClaims{VPToken: VPToken{
			presentationDefinition,
		}},
	}
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

// noVerifier is used when no JWT signature verification is needed.
// To be used with precaution.
type noVerifier struct{}

func (v noVerifier) Verify(_ jose.Headers, _, _, _ []byte) error {
	return nil
}
