/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"github.com/cucumber/godog"
	"github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	credentialServiceURL = "http://localhost:8075"
)

func getProfileIDKey(profileName string) string {
	return profileName + "-profileID"
}

func getProfileAuthToken(profileName string) string {
	// temporary we use org id as token
	return profileName + "-userOrg"
}

// Steps is steps for VC BDD tests
type Steps struct {
	bddContext *context.BDDContext
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.ScenarioContext) {
	s.Step(`^V1 Issuer profile "([^"]*)" for organization "([^"]*)" is created with signatureHolder "([^"]*)", didMethod "([^"]*)", signatureType "([^"]*)" and keyType "([^"]*)"$`, //nolint: lll
		e.createIssuerProfile)
	s.Step(`^V1 We can retrieve issuer profile "([^"]*)" with DID "([^"]*)" and signatureType "([^"]*)"$`, e.checkIssuerProfile)
	s.Step(`^V1 Verifier profile "([^"]*)" for organization "([^"]*)" is created"$`, e.createVerifierProfile)
	s.Step(`^V1 We can retrieve verifier profile "([^"]*)"$`, e.checkVerifierProfile)
	s.Step(`^V1 New verifiable credential is created from "([^"]*)" under "([^"]*)" profile$`, e.createCredential)
	s.Step(`^V1 verifiable credential is verified under "([^"]*)" profile$`, e.verifyCredential)
}
