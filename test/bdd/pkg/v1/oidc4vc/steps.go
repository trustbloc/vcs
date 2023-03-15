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
	"github.com/trustbloc/logutil-go/pkg/log"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

var logger = log.New("oidc4vc-steps")

// Steps defines context for OIDC4VC scenario steps.
type Steps struct {
	// VC issuance
	bddContext          *bddcontext.BDDContext
	issuerProfile       *profileapi.Issuer
	oauthClient         *oauth2.Config // oauthClient is a public client to vcs oidc provider
	cookie              *cookiejar.Jar
	debug               bool
	initiateIssuanceURL string
	authCode            string
	accessToken         string

	// VP
	tlsConfig               *tls.Config
	walletRunner            *walletrunner.Service
	initiateOIDC4VPResponse *walletrunner.InitiateOIDC4VPResponse
	vpFlowExecutor          *walletrunner.VPFlowExecutor

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
			c.InsecureTls = true
			c.DidKeyType = "ECDSAP384DER"
			c.DidMethod = "orb"
		})
	if err != nil {
		return nil, fmt.Errorf("unable create wallet runner: %w", err)
	}

	return &Steps{
		bddContext:   ctx,
		cookie:       jar,
		debug:        false, // set to true to get request/response dumps
		tlsConfig:    tlsConf,
		walletRunner: walletRunner,
	}, nil
}

// RegisterSteps registers OIDC4VC scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^Issuer with id "([^"]*)" is authorized as a Profile user$`, s.authorizeIssuer)
	sc.Step(`^Issuer registers Client for vcs oidc interactions$`, s.registerPublicClient)
	sc.Step(`^User creates the wallet$`, s.createWallet)

	sc.Step(`^Issuer initiates credential issuance using authorization code flow$`, s.initiateCredentialIssuance)
	sc.Step(`^Issuer receives initiate issuance URL$`, s.checkInitiateIssuanceURL)

	sc.Step(`^User interacts with Wallet to initiate OIDC credential issuance$`, s.initiateOIDCCredentialIssuance)
	sc.Step(`^Wallet receives an access token$`, s.checkAccessToken)

	sc.Step(`^Wallet requests credential for claim data$`, s.getCredential)
	sc.Step(`^Wallet receives a valid credential$`, s.checkCredential)

	// VP
	sc.Step(`^User saves credentials into the wallet$`, s.saveCredentialsInWallet)

	sc.Step(`^User interacts with Verifier and initiate OIDC4VP interaction under "([^"]*)" profile for organization "([^"]*)"$`,
		s.initiateInteraction)
	sc.Step(`^User receives authorization request$`, s.verifyAuthorizationRequest)

	sc.Step(`^User invokes authorization request using Wallet$`, s.fetchRequestObjectAndDecodeClaims)
	sc.Step(`^Wallet queries credential that match authorization and display them for User$`, s.queryCredentialFromWallet)

	sc.Step(`^User gives a consent$`, s.checkRequestPresentation)
	sc.Step(`^Wallet sends authorization response$`, s.sendAuthorizedResponse)
	sc.Step(`^Verifier from organization "([^"]*)" retrieves interactions claims$`,
		s.retrieveInteractionsClaim)

	// Stress test
	sc.Step(`^number of users "([^"]*)" making "([^"]*)" concurrent requests$`, s.getUsersNum)
	sc.Step(`^stress test is done$`, s.runStressTest)
	sc.Step(`^metrics are collected and displayed$`, s.displayMetrics)
}
