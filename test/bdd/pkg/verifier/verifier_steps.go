/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cucumber/godog"

	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	"github.com/trustbloc/edge-service/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	verifierHostURL = "http://localhost:8069"
	verifierBaseURL = verifierHostURL + "/verifier"
)

// Steps is steps for VC BDD tests
type Steps struct {
	bddContext *context.BDDContext
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Employer verifies the verifiable credential provided by "([^"]*)"$`, e.credentialsVerification)
	s.Step(`^Employer verifies the verifiable presentation provided by "([^"]*)"$`, e.createAndVerifyPresentation)
	s.Step(`^"([^"]*)" verifies the verifiable credential provided by "([^"]*)"$`, e.verifyCredentialUsingEndppint)
}

func (e *Steps) credentialsVerification(user string) error {
	vc := e.bddContext.Args[bddutil.GetCredentialKey(user)]
	checks := []string{"proof"}

	req := &operation.CredentialsVerificationRequest{
		Credential: []byte(vc),
		Opts: &operation.CredentialsVerificationOptions{
			Checks: checks,
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := verifierBaseURL + "/credentials"

	resp, err := http.Post(endpointURL, "application/json", //nolint: bodyclose
		bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	verificationResp := operation.CredentialsVerificationSuccessResponse{}

	err = json.Unmarshal(respBytes, &verificationResp)
	if err != nil {
		return err
	}

	if len(verificationResp.Checks) != 1 {
		return errors.New("response checks doesn't match the checks in the request")
	}

	return nil
}

func (e *Steps) createAndVerifyPresentation(user string) error {
	vp := e.bddContext.Args[user]
	checks := []string{"proof"}

	req := &operation.VerifyPresentationRequest{
		Presentation: []byte(vp),
		Opts: &operation.VerifyPresentationOptions{
			Checks: checks,
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := verifierBaseURL + "/presentations"

	resp, err := http.Post(endpointURL, "application/json", //nolint: bodyclose
		bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	verificationResp := operation.VerifyPresentationSuccessResponse{}

	err = json.Unmarshal(respBytes, &verificationResp)
	if err != nil {
		return err
	}

	if len(verificationResp.Checks) != 1 {
		return errors.New("response checks doesn't match the checks in the request")
	}

	return nil
}

func (e *Steps) verifyCredentialUsingEndppint(endpoint, user string) error {

	vc := e.bddContext.Args[bddutil.GetCredentialKey(user)]
	checks := []string{"proof"}

	req := &operation.CredentialsVerificationRequest{
		Credential: []byte(vc),
		Opts: &operation.CredentialsVerificationOptions{
			Checks: checks,
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	fmt.Println("request :: ", string(reqBytes))

	return nil
}
