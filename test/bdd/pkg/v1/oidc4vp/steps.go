/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"crypto/tls"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"

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
	bddContext       *bddcontext.BDDContext
	tlsConfig        *tls.Config
	wallet           *wallet.Wallet
	ariesServices    *ariesServices
	walletPassphrase string
	walletToken      string
	walletUserID     string
	walletDidCount   int
	walletDidID      []string
	walletDidKeyID   []string
	vpFlowExecutor   *VPFlowExecutor
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *bddcontext.BDDContext) *Steps {
	return &Steps{
		bddContext: ctx,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		walletDidCount: 1,
	}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.ScenarioContext) {
	s.Step(`^User creates wallet with (\d+) DID$`, e.createWallet)
	s.Step(`^User saves credentials into wallet$`, e.saveCredentialsInWallet)
	s.Step(`^OIDC4VP interaction initiated under "([^"]*)" profile for organization "([^"]*)"$`,
		e.initiateInteraction)
	s.Step(`^OIDC4VP interaction initiated under "([^"]*)" profile for organization "([^"]*)" with fields "([^"]*)"$`,
		e.initiateInteractionWithFields)
	s.Step(`^Verifier form organization "([^"]*)" requests interactions claims$`,
		e.retrieveInteractionsClaim)
	s.Step(`^Verifier form organization "([^"]*)" waits for interaction succeeded event$`,
		e.waitForOIDCInteractionSucceededEvent)
	s.Step(`^Verifier form organization "([^"]*)" requests expired interactions claims$`,
		e.retrieveExpiredOrDeletedInteractionsClaim)
	s.Step(`^Verifier form organization "([^"]*)" requests deleted interactions claims$`,
		e.retrieveExpiredOrDeletedInteractionsClaim)

	s.Step(`^Wallet verify authorization request and decode claims$`, e.verifyAuthorizationRequestAndDecodeClaims)
	s.Step("^Wallet looks for credential that match authorization$", e.queryCredentialFromWallet)
	s.Step("^Wallet send authorization response$", e.sendAuthorizedResponse)

	s.Step(`^"([^"]*)" users execute oidc4vp flow with init "([^"]*)" url, with retrieve "([^"]*)" url, for verify profile "([^"]*)" and org id "([^"]*)" using "([^"]*)" concurrent requests$`,
		e.stressTestForMultipleUsers)
}
