/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"crypto/tls"
	"fmt"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"golang.org/x/oauth2"
	"net/http/cookiejar"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

// Steps defines context for OIDC4VC scenario steps.
type Steps struct {
	// CI
	bddContext          *bddcontext.BDDContext
	issuerProfile       *profileapi.Issuer
	oauthClient         *oauth2.Config // oauthClient is a public client to vcs oidc provider
	cookie              *cookiejar.Jar
	debug               bool
	initiateIssuanceURL string
	authCode            string
	accessToken         string

	// VP
	tlsConfig        *tls.Config
	wallet           *wallet.Wallet
	ariesServices    *ariesServices
	walletPassphrase string
	walletToken      string
	walletUserID     string
	walletDidID      string
	walletDidKeyID   string
	vpFlowExecutor   *VPFlowExecutor
}

// NewSteps returns new Steps context.
func NewSteps(ctx *bddcontext.BDDContext) (*Steps, error) {
	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return nil, fmt.Errorf("init cookie jar: %w", err)
	}

	return &Steps{
		bddContext: ctx,
		cookie:     jar,
		debug:      false, // set to true to get request/response dumps
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
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

	sc.Step(`^User invokes authorization request using Wallet$`, s.fetchRequestRequestObjectAndDecodeClaims)
	sc.Step(`^Wallet queries credential that match authorization and display them for User$`, s.queryCredentialFromWallet)

	sc.Step(`^User gives a consent$`, s.checkRequestPresentation)
	sc.Step(`^Wallet sends authorization response$`, s.sendAuthorizedResponse)
	sc.Step(`^Verifier from organization "([^"]*)" retrieves interactions claims$`,
		s.retrieveInteractionsClaim)
}
