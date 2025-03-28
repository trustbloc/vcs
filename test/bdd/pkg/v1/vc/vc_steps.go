/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"

	"github.com/cucumber/godog"
	"github.com/rdumont/assistdog"

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	credentialServiceURL            = "https://api-gateway.trustbloc.local:5566"
	verifierProfileURL              = "%s/verifier/profiles"
	verifierProfileURLFormat        = verifierProfileURL + "/%s/%s"
	verifyCredentialURLFormat       = verifierProfileURLFormat + "/credentials/verify"
	issuerProfileURL                = "%s/issuer/profiles"
	issuerProfileURLFormat          = issuerProfileURL + "/%s/%s"
	issueCredentialURLFormat        = issuerProfileURLFormat + "/credentials/issue"
	OidcProviderURL                 = "http://cognito-auth.local:8094/cognito"
	updateCredentialStatusURLFormat = "%s/issuer/credentials/status"
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
	s.Step(`^V1 New verifiable credential is issued from "([^"]*)" under "([^"]*)" profile$`, e.issueVC)
	s.Step(`^V1 verifiable credential is verified under "([^"]*)" profile$`, e.verifyVC)
	s.Step(`^V1 "([^"]*)" did unsuccessful attempt to revoke credential: "([^"]*)"$`, e.revokeVCWithError)
	s.Step(`^V1 "([^"]*)" did unsuccessful attempt to activate credential: "([^"]*)"$`, e.activateVCWithError)
	s.Step(`^V1 verifiable credential is successfully revoked under "([^"]*)" profile$`, e.revokeVC)
	s.Step(`^V1 verifiable credential is successfully activated under "([^"]*)" profile$`, e.activateVC)
	s.Step(`^V1 revoked credential is unable to be verified under "([^"]*)" profile$`, e.verifyVCRevoked)

	s.Step(`^V1 "([^"]*)" did unsuccessful attempt to suspend credential: "([^"]*)"$`, e.suspendVCWithError)
	s.Step(`^V1 "([^"]*)" did unsuccessful attempt to unsuspend credential: "([^"]*)"$`, e.unsuspendVCWithError)
	s.Step(`^V1 verifiable credential is successfully suspended under "([^"]*)" profile$`, e.suspendVC)
	s.Step(`^V1 verifiable credential is successfully unsuspended under "([^"]*)" profile$`, e.unsuspendVC)
	s.Step(`^V1 suspended credential is unable to be verified under "([^"]*)" profile$`, e.verifyVCSuspended)

	s.Step(`^V1 verifiable credential is unable to be verified under "([^"]*)" profile error: "([^"]*)"$`, e.verifyVCWithExpectedError)
	s.Step(`^"([^"]*)" users request to create a vc and verify it "([^"]*)" with profiles issuer "([^"]*)" verify "([^"]*)" using "([^"]*)" concurrent requests$`, e.stressTestForMultipleUsers)

	s.Step(`^New verifiable credentials is created from table:$`, e.createCredentialsFromTable)
	s.Step(`^With AccessTokenUrlEnv "([^"]*)", new verifiable credentials is created from table:$`, e.createCredentialsFromTableWithEnv)
}

func (e *Steps) authorizeProfileUser(accessTokenUrlEnv, profileVersionedID, username, password string) error {
	accessTokenURL, err := getEnv(accessTokenUrlEnv, OidcProviderURL)
	if err != nil {
		return err
	}

	issuerProfile, ok := e.bddContext.IssuerProfiles[profileVersionedID]

	if !ok {
		return fmt.Errorf("issuer profile '%s' not found", profileVersionedID)
	}

	accessToken, err := bddutil.IssueAccessToken(context.Background(), accessTokenURL,
		username, password, []string{"org_admin"})
	if err != nil {
		return err
	}

	e.bddContext.Args[getOrgAuthTokenKey(issuerProfile.ID+"/"+issuerProfile.Version)] = accessToken

	e.bddContext.IssuerProfiles[issuerProfile.ID+"/"+issuerProfile.Version] = issuerProfile

	return nil
}

type createVCParams struct {
	IssuerProfile string
	UserName      string
	Password      string
	Credential    string
	VCFormat      string
	DIDIndex      int
}

func (e *Steps) createCredentialsFromTable(table *godog.Table) error {
	return e.createCredentialsFromTableWithEnv("", table)
}

func (e *Steps) createCredentialsFromTableWithEnv(accessTokenURLEnvName string, table *godog.Table) error {
	params, err := assistdog.NewDefault().CreateSlice(&createVCParams{}, table)
	if err != nil {
		return err
	}

	allCreds := make([][]byte, 0)

	for _, p := range params.([]*createVCParams) {

		err := e.authorizeProfileUser(accessTokenURLEnvName, p.IssuerProfile, p.UserName, p.Password)
		if err != nil {
			return err
		}

		chunks := strings.Split(p.IssuerProfile, "/")
		profileID, profileVersion := chunks[0], chunks[1]
		_, err = e.createCredential(
			credentialServiceURL,
			p.Credential, profileID, profileVersion, p.DIDIndex)
		if err != nil {
			return err
		}
		allCreds = append(allCreds, e.bddContext.CreatedCredential)
	}

	e.bddContext.CreatedCredentialsSet = allCreds
	return nil
}
