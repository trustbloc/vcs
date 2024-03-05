/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"

	"github.com/cucumber/godog"
	"github.com/piprate/json-gold/ld"
	lddocloader "github.com/trustbloc/did-go/doc/ld/documentloader"
	"github.com/trustbloc/did-go/legacy/mem"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	"github.com/trustbloc/did-go/vdr"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/kms-go/wrapper/localsuite"
	longform "github.com/trustbloc/sidetree-go/pkg/vdr/sidetreelongform"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/trustregistry"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wellknown"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

const (
	attestationServiceURL = "https://mock-attestation.trustbloc.local:8097/profiles/profileID/profileVersion/wallet/attestation"
	trustRegistryHost     = "https://mock-trustregistry.trustbloc.local:8098"
)

// Steps defines context for OIDC4VC scenario steps.
type Steps struct {
	bddContext       *bddcontext.BDDContext
	tlsConfig        *tls.Config
	cookie           *cookiejar.Jar
	oidc4vciProvider *oidc4vciProvider
	oidc4vpProvider  *oidc4vpProvider
	documentLoader   *lddocloader.DocumentLoader
	issuerProfile    *profileapi.Issuer
	verifierProfile  *profileapi.Verifier
	wallet           *wallet.Wallet
	wellKnownService *wellknown.Service

	issuedCredentialType       string
	issuedCredentialTemplateID string
	vpClaimsTransactionID      string
	presentationDefinitionID   string

	// Stress testing
	usersNum      int
	concurrentReq int
	stressResult  *stress.Result
	proofType     string
}

// NewSteps returns new Steps context.
func NewSteps(ctx *bddcontext.BDDContext) (*Steps, error) {
	s := &Steps{
		bddContext: ctx,
	}

	if err := s.ResetAndSetup(); err != nil {
		return nil, err
	}

	return s, nil
}

// RegisterSteps registers OIDC4VC scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^Profile "([^"]*)" issuer has been authorized with username "([^"]*)" and password "([^"]*)"$`, s.authorizeIssuerProfileUser)
	sc.Step(`^Profile "([^"]*)" verifier has been authorized with username "([^"]*)" and password "([^"]*)"$`, s.authorizeVerifierProfileUser)
	sc.Step(`^User holds credential "([^"]*)" with templateID "([^"]*)"$`, s.credentialTypeTemplateID)
	sc.Step(`^User saves issued credentials`, s.saveCredentials)
	sc.Step(`^credential is issued$`, s.checkIssuedCredential)
	sc.Step(`^issued credential history is updated`, s.checkIssuedCredentialHistoryStep)

	// OIDC4VCI
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow$`, s.runOIDC4VCIAuth)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow with credential configuration ID "([^"]*)"$`, s.runOIDC4VCIAuthWithCredentialConfigurationID)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow with scopes "([^"]*)"$`, s.runOIDC4VCIAuthWithScopes)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow with client registration method "([^"]*)"$`, s.runOIDC4CIAuthWithClientRegistrationMethod)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow with wallet-initiated$`, s.runOIDC4VCIAuthWalletInitiatedFlow)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow$`, s.runOIDC4CIPreAuthWithValidClaims)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow with invalid claims schema$`, s.runOIDC4VCIAuthWithInvalidClaims)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow with client attestation enabled$`, s.runOIDC4CIPreAuthWithClientAttestation)
	sc.Step(`^proofType is "([^"]*)"$`, s.setProofType)
	// OIDC4VP
	sc.Step(`^User interacts with Verifier and initiate OIDC4VP interaction under "([^"]*)" profile with presentation definition ID "([^"]*)" and fields "([^"]*)"$`, s.runOIDC4VPFlow)
	sc.Step(`^User interacts with Verifier and initiate OIDC4VP interaction under "([^"]*)" profile with presentation definition ID "([^"]*)" and fields "([^"]*)" and custom scopes "([^"]*)"$`, s.runOIDC4VPFlowWithCustomScopes)
	sc.Step(`^Verifier with profile "([^"]*)" retrieves interactions claims$`, s.retrieveInteractionsClaim)
	sc.Step(`^Verifier with profile "([^"]*)" retrieves interactions claims with additional claims associated with custom scopes "([^"]*)"$`, s.retrieveInteractionsClaimWithCustomScopes)
	sc.Step(`^wallet configured to use hardcoded vp_token format "([^"]*)" for OIDC4VP interaction$`, s.setHardcodedVPTokenFormat)

	// Error cases
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow with invalid claims$`, s.runOIDC4VCIPreAuthWithInvalidClaims)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow with invalid claims schema$`, s.initiateCredentialIssuanceWithClaimsSchemaValidationError)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow and receives "([^"]*)" error$`, s.runOIDC4CIPreAuthWithError)
	sc.Step(`^Verifier with profile "([^"]*)" requests deleted interactions claims$`, s.retrieveExpiredOrDeletedInteractionsClaim)
	sc.Step(`^Verifier with profile "([^"]*)" requests expired interactions claims$`, s.retrieveExpiredOrDeletedInteractionsClaim)
	sc.Step(`^Verifier with profile "([^"]*)" waits for interaction succeeded event$`, s.waitForOIDCInteractionSucceededEvent)
	sc.Step(`^User interacts with Verifier and initiate OIDC4VP interaction under "([^"]*)" profile with presentation definition ID "([^"]*)" and fields "([^"]*)" and receives "([^"]*)" error$`, s.runOIDC4VPFlowWithError)
	sc.Step(`^Malicious attacker stealing auth code from User and using "([^"]*)" ClientID makes /token request and receives "([^"]*)" error$`, s.runOIDC4CIAuthWithErrorInvalidClient)
	sc.Step(`^Malicious attacker changed JWT kid header and makes /credential request and receives "([^"]*)" error$`, s.runOIDC4VCIAuthWithErrorInvalidSigningKeyID)
	sc.Step(`^Malicious attacker changed signature value and makes /credential request and receives "([^"]*)" error$`, s.runOIDC4VCIAuthWithErrorInvalidSignatureValue)
	sc.Step(`^Malicious attacker changed nonce value and makes /credential request and receives "([^"]*)" error$`, s.runOIDC4VCIAuthWithErrorInvalidNonce)
	sc.Step(`^User initiates credential issuance flow and receives "([^"]*)" error$`, s.initiateCredentialIssuanceWithError)

	// Stress tests
	sc.Step(`^number of users "([^"]*)" making "([^"]*)" concurrent requests$`, s.getUsersNum)
	sc.Step(`^stress test is done$`, s.runStressTest)
	sc.Step(`^metrics are collected and displayed$`, s.displayMetrics)
}

func (s *Steps) ResetAndSetup() error {
	s.tlsConfig = nil
	s.cookie = nil
	s.oidc4vciProvider = nil
	s.oidc4vpProvider = nil
	s.documentLoader = nil
	s.issuerProfile = nil
	s.verifierProfile = nil
	s.wallet = nil
	s.wellKnownService = nil
	s.issuedCredentialType = ""
	s.issuedCredentialTemplateID = ""
	s.vpClaimsTransactionID = ""
	s.presentationDefinitionID = ""
	s.usersNum = 0
	s.concurrentReq = 0
	s.stressResult = nil
	s.proofType = "jwt"

	s.tlsConfig = s.bddContext.TLSConfig

	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return fmt.Errorf("init cookie jar: %w", err)
	}

	s.cookie = jar

	documentLoader, err := bddutil.DocumentLoader()
	if err != nil {
		return err
	}

	s.documentLoader = documentLoader

	longForm, err := longform.New()
	if err != nil {
		return fmt.Errorf("init ion vdr: %w", err)
	}

	vdRegistry := vdr.New(
		vdr.WithVDR(longForm),
		vdr.WithVDR(key.New()),
		vdr.WithVDR(jwk.New()),
	)

	storageProvider := mem.NewProvider()

	kmsStore, err := kms.NewAriesProviderWrapper(storageProvider)
	if err != nil {
		return fmt.Errorf("init kms store: %w", err)
	}

	suite, err := localsuite.NewLocalCryptoSuite("local-lock://wallet-cli", kmsStore, &noop.NoLock{})
	if err != nil {
		return fmt.Errorf("init local crypto suite: %w", err)
	}

	keyCreator, err := suite.RawKeyCreator()
	if err != nil {
		return fmt.Errorf("init key creator: %w", err)
	}

	w, err := wallet.New(
		&walletProvider{
			storageProvider: storageProvider,
			documentLoader:  documentLoader,
			vdRegistry:      vdRegistry,
			keyCreator:      keyCreator,
		},
		wallet.WithNewDID("ion"),
		wallet.WithKeyType("ECDSAP384DER"),
	)
	if err != nil {
		return fmt.Errorf("init wallet: %w", err)
	}

	s.wallet = w

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: s.bddContext.TLSConfig,
		},
	}

	wellKnownService := &wellknown.Service{
		HTTPClient:  httpClient,
		VDRRegistry: vdRegistry,
	}

	s.wellKnownService = wellKnownService

	attestationService, err := attestation.NewService(
		&attestationProvider{
			storageProvider: storageProvider,
			httpClient:      httpClient,
			documentLoader:  documentLoader,
			cryptoSuite:     suite,
			wallet:          w,
		},
		attestationServiceURL,
		0,
	)
	if err != nil {
		return fmt.Errorf("create attestation service: %w", err)
	}

	trustRegistry := trustregistry.NewClient(httpClient, trustRegistryHost)

	s.oidc4vciProvider = &oidc4vciProvider{
		storageProvider:    storageProvider,
		httpClient:         httpClient,
		documentLoader:     documentLoader,
		vdrRegistry:        vdRegistry,
		cryptoSuite:        suite,
		attestationService: attestationService,
		trustRegistry:      trustRegistry,
		wallet:             w,
		wellKnownService:   wellKnownService,
	}

	s.oidc4vpProvider = &oidc4vpProvider{
		storageProvider:    storageProvider,
		httpClient:         httpClient,
		documentLoader:     documentLoader,
		vdrRegistry:        vdRegistry,
		cryptoSuite:        suite,
		attestationService: attestationService,
		trustRegistry:      trustRegistry,
		wallet:             w,
	}

	return nil
}

type walletProvider struct {
	storageProvider storageapi.Provider
	documentLoader  ld.DocumentLoader
	vdRegistry      vdrapi.Registry
	keyCreator      api.RawKeyCreator
}

func (p *walletProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *walletProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *walletProvider) VDRegistry() vdrapi.Registry {
	return p.vdRegistry
}

func (p *walletProvider) KeyCreator() api.RawKeyCreator {
	return p.keyCreator
}

type attestationProvider struct {
	storageProvider storageapi.Provider
	httpClient      *http.Client
	documentLoader  ld.DocumentLoader
	cryptoSuite     api.Suite
	wallet          *wallet.Wallet
}

func (p *attestationProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *attestationProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *attestationProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *attestationProvider) CryptoSuite() api.Suite {
	return p.cryptoSuite
}

func (p *attestationProvider) Wallet() *wallet.Wallet {
	return p.wallet
}
