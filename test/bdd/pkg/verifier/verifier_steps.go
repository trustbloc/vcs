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

	"github.com/trustbloc/edge-service/pkg/restapi/verifier/operation"
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
	s.Step(`^"([^"]*)" verifies the verifiable credential provided by "([^"]*)"$`, e.verifyCredentialUsingEndpoint)
	s.Step(`^"([^"]*)" verifies the verifiable presentation provided by "([^"]*)"$`, e.verifyPresentationUsingEndpoint)
}

func (e *Steps) credentialsVerification(user string) error {
	vc := e.bddContext.Args[bddutil.GetCredentialKey(user)]
	opts := &operation.CredentialsVerificationOptions{
		Checks:    []string{"proof"},
		Challenge: e.bddContext.Args[bddutil.GetProofChallengeKey(user)],
		Domain:    e.bddContext.Args[bddutil.GetProofDomainKey(user)],
	}

	return e.verifyCredential(verifierBaseURL+"/credentials", []byte(vc), opts)
}

func (e *Steps) createAndVerifyPresentation(user string) error {
	vp := e.bddContext.Args[user]
	opts := &operation.VerifyPresentationOptions{
		Checks:    []string{"proof"},
		Challenge: e.bddContext.Args[bddutil.GetProofChallengeKey(user)],
		Domain:    e.bddContext.Args[bddutil.GetProofDomainKey(user)],
	}

	return e.verifyPresentation(verifierBaseURL+"/presentations", []byte(vp), opts)
}

func (e *Steps) verifyCredentialUsingEndpoint(endpoint, user string) error {
	vc := e.bddContext.Args[bddutil.GetCredentialKey(user)]
	opts := &operation.CredentialsVerificationOptions{
		Checks: []string{"proof"},
	}

	return e.verifyCredential(endpoint, []byte(vc), opts)
}

func (e *Steps) verifyPresentationUsingEndpoint(endpoint, user string) error {
	vp := e.bddContext.Args[bddutil.GetPresentationKey(user)]

	userOpts, ok := e.bddContext.Args[bddutil.GetOptionsKey(user)]
	if !ok {
		return fmt.Errorf("unable to find verification for user: %s", user)
	}

	opts := &operation.VerifyPresentationOptions{}

	err := json.Unmarshal([]byte(userOpts), opts)
	if err != nil {
		return err
	}

	return e.verifyPresentation(endpoint, []byte(vp), opts)
}

func (e *Steps) verifyCredential(endpoint string, vc []byte, opts *operation.CredentialsVerificationOptions) error {
	req := &operation.CredentialsVerificationRequest{
		Credential: vc,
		Opts:       opts,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	return e.verify(endpoint, reqBytes)
}

func (e *Steps) verifyPresentation(endpoint string, vp []byte, opts *operation.VerifyPresentationOptions) error {
	req := &operation.VerifyPresentationRequest{
		Presentation: vp,
		Opts:         opts,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	return e.verify(endpoint, reqBytes)
}

func (e *Steps) verify(endpoint string, reqBytes []byte) error {
	resp, err := http.Post(endpoint, "application/json", //nolint: bodyclose, gosec
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

	verificationResp := struct {
		Checks []string `json:"checks,omitempty"`
	}{}

	err = json.Unmarshal(respBytes, &verificationResp)
	if err != nil {
		return err
	}

	if len(verificationResp.Checks) != 1 {
		return errors.New("response checks doesn't match the checks in the request")
	}

	return nil
}
