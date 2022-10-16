/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4vp_service_mocks_test.go -self_package mocks -package oidc4vp_test -source=oidc4vp_service.go -mock_names transactionManager=MockTransactionManager,events=MockEvents,kmsRegistry=MockKMSRegistry,requestObjectPublicStore=MockRequestObjectPublicStore,profileService=MockProfileService,presentationVerifier=MockPresentationVerifier

package oidc4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/internal/pkg/log"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

var logger = log.New("oidc4vp-service")

var ErrDataNotFound = errors.New("data not found")

type InteractionInfo struct {
	AuthorizationRequest string
	TxID                 TxID
}

type eventService interface {
	Publish(topic string, messages ...*spi.Event) error
}

type transactionManager interface {
	CreateTx(pd *presexch.PresentationDefinition, profileID string) (*Transaction, string, error)
	StoreReceivedClaims(txID TxID, claims *ReceivedClaims) error
	GetByOneTimeToken(nonce string) (*Transaction, bool, error)
}

type requestObjectPublicStore interface {
	Publish(requestObject string) (string, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Verifier, error)
}

type presentationVerifier interface {
	VerifyPresentation(
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
	PresentationVerifier     presentationVerifier
	VDR                      vdrapi.Registry

	RedirectURL   string
	TokenLifetime time.Duration
}

type Service struct {
	eventSvc                 eventService
	transactionManager       transactionManager
	requestObjectPublicStore requestObjectPublicStore
	kmsRegistry              kmsRegistry
	documentLoader           ld.DocumentLoader
	profileService           profileService
	presentationVerifier     presentationVerifier
	vdr                      vdrapi.Registry

	redirectURL   string
	tokenLifetime time.Duration
}

type RequestObjectRegistration struct {
	ClientName                  string           `json:"client_name"`
	SubjectSyntaxTypesSupported []string         `json:"subject_syntax_types_supported"`
	VPFormats                   *presexch.Format `json:"vp_formats"`
	ClientPurpose               string           `json:"client_purpose"`
}

type eventPayload struct {
	TxID string `json:"txID"`
}

func NewService(cfg *Config) *Service {
	return &Service{
		eventSvc:                 cfg.EventSvc,
		transactionManager:       cfg.TransactionManager,
		requestObjectPublicStore: cfg.RequestObjectPublicStore,
		kmsRegistry:              cfg.KMSRegistry,
		documentLoader:           cfg.DocumentLoader,
		profileService:           cfg.ProfileService,
		presentationVerifier:     cfg.PresentationVerifier,
		redirectURL:              cfg.RedirectURL,
		tokenLifetime:            cfg.TokenLifetime,
		vdr:                      cfg.VDR,
	}
}

func (s *Service) sendEvent(tx *Transaction, source string, eventType spi.EventType) error {
	payload, err := json.Marshal(eventPayload{
		TxID: string(tx.ID),
	})
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(spi.VerifierEventTopic, spi.NewEvent(uuid.NewString(), source, eventType, payload))
}

func (s *Service) InitiateOidcInteraction(presentationDefinition *presexch.PresentationDefinition, purpose string,
	profile *profileapi.Verifier) (*InteractionInfo, error) {
	if profile.SigningDID == nil {
		return nil, errors.New("profile signing did can't be nil")
	}

	tx, nonce, err := s.transactionManager.CreateTx(presentationDefinition, profile.ID)
	if err != nil {
		return nil, fmt.Errorf("fail to create oidc tx: %w", err)
	}

	if errSendEvent := s.sendEvent(tx, profile.URL, spi.VerifierOIDCInteractionInitiated); errSendEvent != nil {
		return nil, errSendEvent
	}

	token, err := s.createRequestObjectJWT(presentationDefinition, tx, nonce, purpose, profile)
	if err != nil {
		return nil, err
	}

	requestURI, err := s.requestObjectPublicStore.Publish(token)
	if err != nil {
		return nil, fmt.Errorf("fail publish request object: %w", err)
	}

	return &InteractionInfo{
		AuthorizationRequest: "openid-vc://?request_uri=" + requestURI,
		TxID:                 tx.ID,
	}, nil
}

func (s *Service) VerifyOIDCVerifiablePresentation(txID TxID, nonce string, vp *verifiable.Presentation) error {
	tx, validNonce, err := s.transactionManager.GetByOneTimeToken(nonce)
	if err != nil {
		return fmt.Errorf("get tx by nonce failed: %w", err)
	}

	if !validNonce || tx.ID != txID {
		return fmt.Errorf("invalid nonce")
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID)
	if err != nil {
		return fmt.Errorf("inconsistent transaction state %w", err)
	}

	vpBytes, err := vp.MarshalJSON()
	if err != nil {
		return err
	}

	logger.Info("vp string: %s", log.WithJSON(string(vpBytes)))

	// TODO: should domain and challenge be verified?
	vr, err := s.presentationVerifier.VerifyPresentation(vp, nil, profile)
	if err != nil {
		return fmt.Errorf("presentation verification failed: %w", err)
	}

	if len(vr) > 0 {
		return fmt.Errorf("presentation verification checks failed: %s", vr[0].Error)
	}

	return s.extractClaimData(tx, vp, profile)
}

func (s *Service) extractClaimData(tx *Transaction, vp *verifiable.Presentation, profile *profileapi.Verifier) error {
	// TODO: think about better solution. If jwt is set, its wrap vp into sub object "vp" and this breaks Match
	vp.JWT = ""
	credentials, err := tx.PresentationDefinition.Match(vp, s.documentLoader,
		presexch.WithCredentialOptions(
			verifiable.WithJSONLDDocumentLoader(s.documentLoader),
			verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher()),
		))

	if err != nil {
		return fmt.Errorf("extract claims: match: %w", err)
	}

	err = s.transactionManager.StoreReceivedClaims(tx.ID, &ReceivedClaims{Credentials: credentials})
	if err != nil {
		return fmt.Errorf("extract claims: store: %w", err)
	}

	if err := s.sendEvent(tx, profile.URL, spi.VerifierOIDCInteractionSucceeded); err != nil {
		return err
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

	vcsSigner, err := kms.NewVCSigner(profile.SigningDID.Creator, signingAlgorithm)
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
