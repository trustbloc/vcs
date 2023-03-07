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
	"github.com/rdumont/assistdog"

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	credentialServiceURL            = "https://api-gateway.trustbloc.local:5566"
	verifierProfileURL              = "%s/verifier/profiles"
	verifierProfileURLFormat        = verifierProfileURL + "/%s"
	verifyCredentialURLFormat       = verifierProfileURLFormat + "/credentials/verify"
	issuerProfileURL                = "%s/issuer/profiles"
	issuerProfileURLFormat          = issuerProfileURL + "/%s"
	issueCredentialURLFormat        = issuerProfileURLFormat + "/credentials/issue"
	OidcProviderURL                 = "http://cognito-mock.trustbloc.local:9229/local_5a9GzRvB"
	updateCredentialStatusURLFormat = issuerProfileURLFormat + "/credentials/status"
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
	s.Step(`^V1 verifiable credential is revoked under "([^"]*)" profile for organization "([^"]*)"$`,
		e.revokeVC)
	s.Step(`^V1 verifiable credential is unable to be verified under "([^"]*)" profile for organization "([^"]*)"$`,
		e.verifyRevokedVC)
	s.Step(`^"([^"]*)" users request to create a vc and verify it "([^"]*)" with profiles issuer "([^"]*)" verify "([^"]*)" and org id "([^"]*)" using "([^"]*)" concurrent requests$`,
		e.stressTestForMultipleUsers)

	s.Step(`^New verifiable credentials is created from table:$`,
		e.createCredentialsFromTable)
}

func (e *Steps) authorizeOrganization(org, clientID, secret string) error {
	accessToken, err := bddutil.IssueAccessToken(context.Background(), OidcProviderURL,
		clientID, secret, []string{"org_admin"})
	if err != nil {
		return err
	}

	e.bddContext.Args[getOrgAuthTokenKey(org)] = accessToken

	return nil
}

type createVCParams struct {
	IssuerProfile string
	Organization  string
	Credential    string
	VCFormat      string
	DIDIndex      int
}

func (e *Steps) createCredentialsFromTable(table *godog.Table) error {
	params, err := assistdog.NewDefault().CreateSlice(&createVCParams{}, table)
	if err != nil {
		return err
	}

	allCreds := make([][]byte, 0)

	for _, p := range params.([]*createVCParams) {

		err = e.createCredential(credentialServiceURL, p.Credential, p.VCFormat, p.IssuerProfile, p.Organization, p.DIDIndex)
		if err != nil {
			return err
		}
		allCreds = append(allCreds, e.bddContext.CreatedCredential)
	}

	e.bddContext.CreatedCredentialsSet = allCreds
	return nil
}
