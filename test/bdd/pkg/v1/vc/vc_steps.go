/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/cucumber/godog"

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	credentialServiceURL      = "https://localhost:4455"
	verifierProfileURL        = "%s/verifier/profiles"
	verifierProfileURLFormat  = verifierProfileURL + "/%s"
	verifyCredentialURLFormat = verifierProfileURLFormat + "/credentials/verify"
	issuerProfileURL          = "%s/issuer/profiles"
	issuerProfileURLFormat    = issuerProfileURL + "/%s"
	issueCredentialURLFormat  = issuerProfileURLFormat + "/credentials/issue"
	oidcProviderURL           = "https://localhost:4444"
)

func getOrgAuthTokenKey(org string) string {
	return org + "-accessToken"
}

// Steps is steps for VC BDD tests
type Steps struct {
	sync.RWMutex
	bddContext *bddcontext.BDDContext
	tlsConfig  *tls.Config
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
	s.Step(`^Organization "([^"]*)" has been authorized with client id "([^"]*)" and secret "([^"]*)"$`,
		e.authorizeOrganization)
	s.Step(`^"([^"]*)" Organization "([^"]*)" has been authorized with client id "([^"]*)" and secret "([^"]*)"$`,
		e.authorizeOrganizationForStressTest)
	s.Step(`^V1 New verifiable credential is created from "([^"]*)" in "([^"]*)" format under "([^"]*)" profile for organization "([^"]*)" with signature representation "([^"]*)"$`,
		e.issueVC)
	s.Step(`^V1 verifiable credential is verified under "([^"]*)" profile for organization "([^"]*)"$`,
		e.verifyVC)
	s.Step(`^"([^"]*)" users request to create a vc and verify it "([^"]*)" with profiles issuer "([^"]*)" verify "([^"]*)" and org id "([^"]*)" using "([^"]*)" concurrent requests$`,
		e.stressTestForMultipleUsers)
}

func (e *Steps) authorizeOrganization(org, clientID, secret string) error {
	accessToken, err := bddutil.IssueAccessToken(context.Background(), oidcProviderURL,
		clientID, secret, []string{"org_admin"})
	if err != nil {
		return err
	}

	e.bddContext.Args[getOrgAuthTokenKey(org)] = accessToken

	return nil
}
