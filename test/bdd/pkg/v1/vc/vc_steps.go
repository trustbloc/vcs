/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"context"
	"crypto/tls"

	"github.com/cucumber/godog"

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	credentialServiceURL = "https://localhost:4455"
)

func getProfileIDKey(profileName string) string {
	return profileName + "-profileID"
}

func getOrgAuthTokenKey(org string) string {
	return org + "-accessToken"
}

// Steps is steps for VC BDD tests
type Steps struct {
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
	s.Step(`^V1 Issuer profile "([^"]*)" for organization "([^"]*)" is created with signatureHolder "([^"]*)", didMethod "([^"]*)", signatureType "([^"]*)" and keyType "([^"]*)"$`, //nolint: lll
		e.createIssuerProfile)
	s.Step(`^V1 We can retrieve issuer profile "([^"]*)" with DID "([^"]*)" and signatureType "([^"]*)" for organization "([^"]*)"$`,
		e.checkIssuerProfile)
	s.Step(`^V1 Verifier profile "([^"]*)" for organization "([^"]*)" is created"$`, e.createVerifierProfile)
	s.Step(`^V1 We can retrieve verifier profile "([^"]*)" for organization "([^"]*)"$`, e.checkVerifierProfile)
	s.Step(`^V1 New verifiable credential is created from "([^"]*)" under "([^"]*)" profile for organization "([^"]*)"$`,
		e.createCredential)
	s.Step(`^V1 verifiable credential is verified under "([^"]*)" profile for organization "([^"]*)"$`,
		e.verifyCredential)
}

func (e *Steps) authorizeOrganization(org, clientID, secret string) error {
	accessToken, err := bddutil.IssueAccessToken(context.Background(), clientID, secret, []string{"org_admin"})
	if err != nil {
		return err
	}

	e.bddContext.Args[getOrgAuthTokenKey(org)] = accessToken

	return nil
}
