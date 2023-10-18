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
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

var logger = log.New("oidc4vp-service")

const vpSubmissionProperty = "presentation_submission"

var ErrDataNotFound = errors.New("data not found")

type eventService interface {
	Publish(ctx context.Context, topic string, messages ...*spi.Event) error
}

type transactionManager interface {
	CreateTx(pd *presexch.PresentationDefinition, profileID, profileVersion string) (*Transaction, string, error)
	StoreReceivedClaims(txID TxID, claims *ReceivedClaims) error
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

type eventPayload struct {
	WebHook        string `json:"webHook,omitempty"`
	ProfileID      string `json:"profileID,omitempty"`
	ProfileVersion string `json:"profileVersion,omitempty"`
	OrgID          string `json:"orgID,omitempty"`
	Error          string `json:"error,omitempty"`
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
		metrics:                  metrics,
	}
}

func (s *Service) createEvent(tx *Transaction, profile *profileapi.Verifier,
	eventType spi.EventType, e error) (*spi.Event, error) {
	ep := eventPayload{
		WebHook:        profile.WebHook,
		ProfileID:      profile.ID,
		ProfileVersion: profile.Version,
		OrgID:          profile.OrganizationID,
	}

	if e != nil {
		ep.Error = e.Error()
	}

	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	event := spi.NewEventWithPayload(uuid.NewString(), "source://vcs/verifier", eventType, payload)
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
	logger.Debugc(ctx, "sending Failed OIDC verifier event error, ignoring..", log.WithError(e))
}

func (s *Service) InitiateOidcInteraction(
	ctx context.Context,
	presentationDefinition *presexch.PresentationDefinition,
	purpose string,
	profile *profileapi.Verifier,
) (*InteractionInfo, error) {
	logger.Debugc(ctx, "InitiateOidcInteraction begin")

	if profile.SigningDID == nil {
		return nil, errors.New("profile signing did can't be nil")
	}

	tx, nonce, err := s.transactionManager.CreateTx(presentationDefinition, profile.ID, profile.Version)
	if err != nil {
		return nil, fmt.Errorf("fail to create oidc tx: %w", err)
	}

	logger.Debugc(ctx, "InitiateOidcInteraction tx created", log.WithTxID(string(tx.ID)))

	if errSendEvent := s.sendEvent(ctx, tx, profile, spi.VerifierOIDCInteractionInitiated); errSendEvent != nil {
		return nil, errSendEvent
	}

	token, err := s.createRequestObjectJWT(presentationDefinition, tx, nonce, purpose, profile)
	if err != nil {
		return nil, err
	}

	logger.Debugc(ctx, "InitiateOidcInteraction request object created")

	requestURI, err := s.requestObjectPublicStore.Publish(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("fail publish request object: %w", err)
	}

	logger.Debugc(ctx, "InitiateOidcInteraction request object published")

	logger.Debugc(ctx, "InitiateOidcInteraction succeed")

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
			if !lo.Contains(profile.Checks.Presentation.Format, token.VpTokenFormat) {
				e := fmt.Errorf("profile does not support %s vp_token format", token.VpTokenFormat)
				s.sendFailedEvent(ctx, tx, profile, e)

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
		logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation verified")
	}
	wg.Wait()

	if len(validationErrors) > 0 {
		return nil, validationErrors[0]
	}

	return verifiedPresentations, nil
}

func (s *Service) VerifyOIDCVerifiablePresentation(ctx context.Context, txID TxID, tokens []*ProcessedVPToken) error {
	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation begin")
	startTime := time.Now()

	defer func() {
		logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation", log.WithDuration(time.Since(startTime)))
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

	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation nonce verified")

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		return fmt.Errorf("inconsistent transaction state %w", err)
	}

	if errSendEvent := s.sendEvent(ctx, tx, profile, spi.VerifierOIDCInteractionQRScanned); errSendEvent != nil {
		return errSendEvent
	}

	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation profile fetched", logfields.WithProfileID(profile.ID))

	logger.Debugc(ctx, fmt.Sprintf("VerifyOIDCVerifiablePresentation count of tokens is %v", len(tokens)))

	verifiedPresentations, err := s.verifyTokens(ctx, tx, profile, tokens)
	if err != nil {
		return err
	}

	err = s.extractClaimData(ctx, tx, tokens, profile, verifiedPresentations)
	if err != nil {
		s.sendFailedEvent(ctx, tx, profile, err)

		return err
	}

	logger.Debugc(ctx, "extractClaimData claims stored")

	if err = s.sendEvent(ctx, tx, profile, spi.VerifierOIDCInteractionSucceeded); err != nil {
		return err
	}

	logger.Debugc(ctx, "VerifyOIDCVerifiablePresentation succeed")
	return nil
}

func (s *Service) GetTx(_ context.Context, id TxID) (*Transaction, error) {
	return s.transactionManager.Get(id)
}

func (s *Service) RetrieveClaims(ctx context.Context, tx *Transaction) map[string]CredentialMetadata {
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

		//TODO: review this code change. This code shouldn't be dependent on how vc-go serialize
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

		if credContents.Issuer != nil {
			credMeta.Issuer = verifiable.IssuerToJSON(*credContents.Issuer)
		}

		result[credContents.ID] = credMeta
	}
	logger.Debugc(ctx, "RetrieveClaims succeed")

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
	tokens []*ProcessedVPToken,
	profile *profileapi.Verifier,
	verifiedPresentations map[string]*ProcessedVPToken,
) error {
	var presentations []*verifiable.Presentation

	for _, token := range tokens {
		// TODO: think about better solution. If jwt is set, its wrap vp into sub object "vp" and this breaks Match
		token.Presentation.JWT = ""
		presentations = append(presentations, token.Presentation)
	}
	diVerifier, err := s.getDataIntegrityVerifier()
	if err != nil {
		return fmt.Errorf("get data integrity verifier: %w", err)
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

			logger.Debugc(ctx, "vc subject verified")
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
	subjectID, err := verifiable.SubjectID(cred.Contents().Subject)
	if err != nil {
		return fmt.Errorf("fail to parse credential as jwt: %w", err)
	}

	if cred.IsJWT() {
		// We use this strange code, because cred.JWTClaims(false) not take to account "sub" claim from jwt
		_, rawClaims, credErr := jwt.Parse(
			cred.JWTEnvelope.JWT,
			jwt.WithProofChecker(&noVerifier{}),
			jwt.WithIgnoreClaimsMapDecoding(true),
		)
		if credErr != nil {
			return fmt.Errorf("fail to parse credential as jwt: %w", credErr)
		}

		subjectID = fastjson.GetString(rawClaims, "sub")
	}

	if token.SignerDIDID != subjectID {
		return fmt.Errorf("vc subject(%s) does not match with vp signer(%s)",
			subjectID, token.SignerDIDID)
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

	vpFormats := GetSupportedVPFormats(
		kms.SupportedKeyTypes(), profile.Checks.Presentation.Format, profile.Checks.Credential.Format)

	ro := s.createRequestObject(presentationDefinition, vpFormats, tx, nonce, purpose, profile)

	signatureTypes := vcsverifiable.GetSignatureTypesByKeyTypeFormat(profile.OIDCConfig.KeyType, vcsverifiable.Jwt)
	if len(signatureTypes) < 1 {
		return "", fmt.Errorf("unsupported jwt key type %s", profile.OIDCConfig.KeyType)
	}

	vcsSigner, err := kms.NewVCSigner(profile.SigningDID.KMSKeyID, signatureTypes[0])
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: get create signer failed: %w", err)
	}

	return singRequestObject(ro, profile, vcsSigner)
}

func singRequestObject(ro *RequestObject, profile *profileapi.Verifier, vcsSigner vc.SignerAlgorithm) (string, error) {
	signer := NewJWSSigner(profile.SigningDID.Creator, vcsSigner)

	token, err := jwt.NewJoseSigned(ro, nil, signer)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: sign token failed: %w", err)
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: serialize token failed: %w", err)
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
			LogoURI:                     profile.LogoURL,
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

func (v noVerifier) CheckJWTProof(_ jose.Headers, _, _, _ []byte) error {
	return nil
}
