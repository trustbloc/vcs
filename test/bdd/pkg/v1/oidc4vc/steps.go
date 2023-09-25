/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"crypto/tls"
	"fmt"
	"net/http/cookiejar"

	"github.com/cucumber/godog"

	lddocloader "github.com/trustbloc/did-go/doc/ld/documentloader"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

// Steps defines context for OIDC4VC scenario steps.
type Steps struct {
	bddContext                 *bddcontext.BDDContext
	tlsConfig                  *tls.Config
	cookie                     *cookiejar.Jar
	issuerProfile              *profileapi.Issuer
	verifierProfile            *profileapi.Verifier
	walletRunner               *walletrunner.Service
	dl                         *lddocloader.DocumentLoader
	issuedCredentialType       string
	issuedCredentialTemplateID string
	vpClaimsTransactionID      string

	presentationDefinitionID string

	// Stress testing
	usersNum      int
	concurrentReq int
	stressResult  *stress.Result

	// Hooks
	oidc4vpHooks *walletrunner.OIDC4VPHooks
}

func (s *Steps) ResetAndSetup() error {
	s.tlsConfig = nil
	s.cookie = nil
	s.issuerProfile = nil
	s.verifierProfile = nil
	s.walletRunner = nil
	s.dl = nil
	s.issuedCredentialType = ""
	s.issuedCredentialTemplateID = ""
	s.vpClaimsTransactionID = ""
	s.presentationDefinitionID = ""
	s.usersNum = 0
	s.concurrentReq = 0
	s.stressResult = nil
	s.oidc4vpHooks = nil

	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return fmt.Errorf("init cookie jar: %w", err)
	}

	if s.walletRunner != nil {
		if s.walletRunner.GetWallet() != nil {
			_ = s.walletRunner.GetWallet().Close()
		}
	}
	walletRunner, err := walletrunner.New(vcprovider.ProviderVCS,
		func(c *vcprovider.Config) {
			c.DidKeyType = "ECDSAP384DER"
			c.DidMethod = "ion"
			c.KeepWalletOpen = true
		})
	if err != nil {
		return fmt.Errorf("unable create wallet runner: %w", err)
	}

	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return err
	}

	s.cookie = jar
	s.tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	s.walletRunner = walletRunner
	s.dl = loader

	return nil
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
	sc.Step(`^Issuer with id "([^"]*)" is authorized as a Profile user$`, s.authorizeIssuer)
	sc.Step(`^User holds credential "([^"]*)" with templateID "([^"]*)"$`, s.credentialTypeTemplateID)
	sc.Step(`^credential is issued$`, s.checkIssuedCredential)

	// CI.
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow$`, s.runOIDC4CIAuth)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow with client registration method "([^"]*)"$`, s.runOIDC4CIAuthWithClientRegistrationMethod)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow with wallet-initiated$`, s.runOIDC4CIAuthWalletInitiatedFlow)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow$`, s.runOIDC4CIPreAuthWithValidClaims)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow with invalid claims schema$`, s.runOIDC4CIAuthWithInvalidClaims)

	// VP.
	sc.Step(`^User interacts with Verifier and initiate OIDC4VP interaction under "([^"]*)" profile for organization "([^"]*)" with presentation definition ID "([^"]*)" and fields "([^"]*)"$`, s.runOIDC4VPFlow)
	sc.Step(`^Verifier from organization "([^"]*)" retrieves interactions claims$`, s.retrieveInteractionsClaim)
	sc.Step(`^wallet configured to use hardcoded vp_token format "([^"]*)" for OIDC4VP interaction$`, s.setHardcodedVPTokenFormat)

	// Errors.
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow with invalid claims$`, s.runOIDC4CIPreAuthWithInvalidClaims)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow with invalid claims schema$`, s.initiateCredentialIssuanceWithClaimsSchemaValidationError)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow and receives "([^"]*)" error$`, s.runOIDC4CIPreAuthWithError)
	sc.Step(`^Verifier form organization "([^"]*)" requests deleted interactions claims$`, s.retrieveExpiredOrDeletedInteractionsClaim)
	sc.Step(`^Verifier form organization "([^"]*)" requests expired interactions claims$`, s.retrieveExpiredOrDeletedInteractionsClaim)
	sc.Step(`^Verifier form organization "([^"]*)" waits for interaction succeeded event$`, s.waitForOIDCInteractionSucceededEvent)
	sc.Step(`^User interacts with Verifier and initiate OIDC4VP interaction under "([^"]*)" profile for organization "([^"]*)" with presentation definition ID "([^"]*)" and fields "([^"]*)" and receives "([^"]*)" error$`, s.runOIDC4VPFlowWithError)
	sc.Step(`^Malicious attacker stealing auth code from User and using "([^"]*)" ClientID makes /token request and receives "([^"]*)" error$`, s.runOIDC4CIAuthWithError)

	// Stress test.
	sc.Step(`^number of users "([^"]*)" making "([^"]*)" concurrent requests$`, s.getUsersNum)
	sc.Step(`^stress test is done$`, s.runStressTest)
	sc.Step(`^metrics are collected and displayed$`, s.displayMetrics)
}
