/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"crypto/tls"

	"github.com/cucumber/godog"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	credentialServiceURL               = "https://api-gateway.trustbloc.local:5566"
	oidc4vpWebhookURL                  = "http://localhost:8180/checktopics"
	verifierProfileURL                 = credentialServiceURL + "/verifier/profiles"
	verifierProfileURLFormat           = verifierProfileURL + "/%s/%s"
	initiateOidcInteractionURLFormat   = verifierProfileURLFormat + "/interactions/initiate-oidc"
	retrieveInteractionsClaimURLFormat = credentialServiceURL + "/verifier/interactions/%s/claim"
)

func getOrgAuthTokenKey(org string) string {
	return org + "-accessToken"
}

// Steps is steps for VC BDD tests
type Steps struct {
	bddContext                 *bddcontext.BDDContext
	tlsConfig                  *tls.Config
	walletRunner               *walletrunner.Service
	vpFlowExecutor             *walletrunner.VPFlowExecutor
	initiateOIDC4VPResponse    *walletrunner.InitiateOIDC4VPResponse
	verifierProfileVersionedID string
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *bddcontext.BDDContext) *Steps {
	return &Steps{
		bddContext: ctx,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.ScenarioContext) {
	s.Step(`^User creates wallet with (\d+) DID$`, e.createWallet)
	s.Step(`^User saves credentials into wallet$`, e.saveCredentialsInWallet)
	s.Step(`^OIDC4VP interaction initiated under "([^"]*)" profile for organization "([^"]*)"$`,
		e.initiateInteraction)
	s.Step(`^Verifier form organization "([^"]*)" requests interactions claims$`,
		e.retrieveInteractionsClaim)

	s.Step(`^Wallet verify authorization request and decode claims$`, e.verifyAuthorizationRequestAndDecodeClaims)
	s.Step("^Wallet looks for credential that match authorization multi VP$", e.queryCredentialFromWalletMultiVP)
	s.Step("^Wallet send authorization response$", e.sendAuthorizedResponse)

	s.Step(`^"([^"]*)" users execute oidc4vp flow with init "([^"]*)" url, with retrieve "([^"]*)" url, for verify profile "([^"]*)" and org id "([^"]*)" using "([^"]*)" concurrent requests$`,
		e.stressTestForMultipleUsers)
}
