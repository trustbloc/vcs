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
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"

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
	dl                         *ld.DocumentLoader
	issuedCredentialType       string
	issuedCredentialTemplateID string
	vpClaimsTransactionID      string

	presentationDefinitionID string

	// Stress testing
	usersNum      int
	concurrentReq int
	stressResult  *stress.Result
}

// NewSteps returns new Steps context.
func NewSteps(ctx *bddcontext.BDDContext) (*Steps, error) {
	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return nil, fmt.Errorf("init cookie jar: %w", err)
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}

	walletRunner, err := walletrunner.New(vcprovider.ProviderVCS,
		func(c *vcprovider.Config) {
			c.DidKeyType = "ECDSAP384DER"
			c.DidMethod = "orb"
			c.KeepWalletOpen = true
		})
	if err != nil {
		return nil, fmt.Errorf("unable create wallet runner: %w", err)
	}

	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return nil, err
	}

	return &Steps{
		bddContext:   ctx,
		cookie:       jar,
		tlsConfig:    tlsConf,
		walletRunner: walletRunner,
		dl:           loader,
	}, nil
}

// RegisterSteps registers OIDC4VC scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^Issuer with id "([^"]*)" is authorized as a Profile user$`, s.authorizeIssuer)
	sc.Step(`^User holds credential "([^"]*)" with templateID "([^"]*)"$`, s.credentialTypeTemplateID)
	sc.Step(`^credential is issued$`, s.checkIssuedCredential)

	// CI.
	sc.Step(`^User interacts with Wallet to initiate credential issuance using authorization code flow$`, s.runOIDC4CIAuth)
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow$`, s.runOIDC4CIPreAuthWithValidClaims)

	// VP.
	sc.Step(`^User interacts with Verifier and initiate OIDC4VP interaction under "([^"]*)" profile for organization "([^"]*)" with presentation definition ID "([^"]*)" and fields "([^"]*)"$`, s.runOIDC4VPFlow)
	sc.Step(`^Verifier from organization "([^"]*)" retrieves interactions claims$`, s.retrieveInteractionsClaim)

	// Errors.
	sc.Step(`^User interacts with Wallet to initiate credential issuance using pre authorization code flow with invalid claims$`, s.runOIDC4CIPreAuthWithInvalidClaims)
	sc.Step(`^Verifier form organization "([^"]*)" requests deleted interactions claims$`, s.retrieveExpiredOrDeletedInteractionsClaim)
	sc.Step(`^Verifier form organization "([^"]*)" requests expired interactions claims$`, s.retrieveExpiredOrDeletedInteractionsClaim)
	sc.Step(`^Verifier form organization "([^"]*)" waits for interaction succeeded event$`, s.waitForOIDCInteractionSucceededEvent)
	sc.Step(`^User interacts with Verifier and initiate OIDC4VP interaction under "([^"]*)" profile for organization "([^"]*)" with presentation definition ID "([^"]*)" and fields "([^"]*)" and receives "([^"]*)" error$`, s.runOIDC4VPFlowWithError)

	// Stress test.
	sc.Step(`^number of users "([^"]*)" making "([^"]*)" concurrent requests$`, s.getUsersNum)
	sc.Step(`^stress test is done$`, s.runStressTest)
	sc.Step(`^metrics are collected and displayed$`, s.displayMetrics)
}
