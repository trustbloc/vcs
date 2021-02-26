/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/trustbloc/edge-service/pkg/doc/vc/profile/verifier"
	"github.com/trustbloc/edge-service/pkg/restapi/verifier/operation"
	"github.com/trustbloc/edge-service/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	verifierHostURL = "http://localhost:8069"

	verifyCredentialURLFormat   = verifierHostURL + "/%s" + "/verifier/credentials"
	verifyPresentationURLFormat = verifierHostURL + "/%s" + "/verifier/presentations"
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
	s.Step(`^Client sends request to create a verifier profile with ID "([^"]*)"$`, e.createBasicVerifierProfile)
	s.Step(`^Client deletes the verifier profile with ID "([^"]*)"$`, e.deleteVerifierProfile)
	s.Step(`^Client can recreate the verifier profile with ID "([^"]*)"$`, e.createBasicVerifierProfile)
	s.Step(`^"([^"]*)" has a profile$`, e.createBasicVerifierProfile)
	s.Step(`^"([^"]*)" verifies the verifiable credential provided by "([^"]*)"$`, e.credentialsVerification)
	s.Step(`^"([^"]*)" verifies the verifiable presentation provided by "([^"]*)" is "([^"]*)" with message "([^"]*)"$`, e.createAndVerifyPresentation) //nolint: lll
	s.Step(`^"([^"]*)" endpoint verifies the verifiable credential provided by "([^"]*)"$`,
		e.verifyCredentialUsingEndpoint)
	s.Step(`^"([^"]*)" endpoint verifies the verifiable presentation provided by "([^"]*)"$`,
		e.verifyPresentationUsingEndpoint)
}

func (e *Steps) credentialsVerification(verifierProfile, user string) error {
	vc := e.bddContext.Args[bddutil.GetCredentialKey(user)]
	opts := &operation.CredentialsVerificationOptions{
		Checks:    []string{"proof"},
		Challenge: e.bddContext.Args[bddutil.GetProofChallengeKey(user)],
		Domain:    e.bddContext.Args[bddutil.GetProofDomainKey(user)],
	}

	return e.verifyCredential(fmt.Sprintf(verifyCredentialURLFormat, verifierProfile), []byte(vc), opts)
}

func (e *Steps) createAndVerifyPresentation(verifierProfile, user, result, respMessage string) error {
	vp := e.bddContext.Args[user]
	opts := &operation.VerifyPresentationOptions{
		Checks:    []string{"proof"},
		Challenge: e.bddContext.Args[bddutil.GetProofChallengeKey(user)],
		Domain:    e.bddContext.Args[bddutil.GetProofDomainKey(user)],
	}

	if strings.Contains(verifierProfile, "revoke") {
		opts.Checks = append(opts.Checks, "credentialStatus")
	}

	return e.verifyPresentation(fmt.Sprintf(verifyPresentationURLFormat, verifierProfile), []byte(vp), opts,
		result, respMessage)
}

func (e *Steps) verifyCredentialUsingEndpoint(endpoint, user string) error {
	vc := e.bddContext.Args[bddutil.GetCredentialKey(user)]
	opts := &operation.CredentialsVerificationOptions{
		Checks: []string{"proof"},
	}

	if endpoint == "" {
		profileID := uuid.New().String()

		err := e.createBasicVerifierProfile(profileID)
		if err != nil {
			return err
		}

		endpoint = fmt.Sprintf(verifyCredentialURLFormat, profileID)
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

	if endpoint == "" {
		profileID := uuid.New().String()

		err := e.createBasicVerifierProfile(profileID)
		if err != nil {
			return err
		}

		endpoint = fmt.Sprintf(verifyPresentationURLFormat, profileID)
	}

	return e.verifyPresentation(endpoint, []byte(vp), opts, "successful", strings.Join(opts.Checks, ","))
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

	return e.verify(endpoint, reqBytes, opts.Checks, "successful", "proof")
}

func (e *Steps) verifyPresentation(endpoint string, vp []byte, opts *operation.VerifyPresentationOptions,
	result, respMessage string) error {
	req := &operation.VerifyPresentationRequest{
		Presentation: vp,
		Opts:         opts,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	return e.verify(endpoint, reqBytes, opts.Checks, result, respMessage)
}

func (e *Steps) verify(endpoint string, reqBytes []byte, checks []string, result, respMessage string) error {
	resp, err := bddutil.HTTPDo(http.MethodPost, endpoint, "application/json", "rw_token", //nolint: bodyclose
		bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if result == "successful" { //nolint:nestif
		if resp.StatusCode != http.StatusOK {
			return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
		}

		verifiedResp := struct {
			Checks []string `json:"checks,omitempty"`
		}{}

		err = json.Unmarshal(respBytes, &verifiedResp)
		if err != nil {
			return err
		}

		respChecks := strings.Split(respMessage, ",")

		if len(respChecks) != len(verifiedResp.Checks) {
			return fmt.Errorf("resp checks %d doesn't equal to requested checks %d", len(verifiedResp.Checks), len(checks))
		}
	} else {
		if resp.StatusCode != http.StatusBadRequest {
			return bddutil.ExpectedStatusCodeError(http.StatusBadRequest, resp.StatusCode, respBytes)
		}

		if !strings.Contains(string(respBytes), respMessage) {
			return fmt.Errorf("resp verified msg %s not contains %s", string(respBytes), respMessage)
		}
	}

	return nil
}

func (e *Steps) createBasicVerifierProfile(profileID string) error {
	profileRequest := &verifier.ProfileData{}

	profileRequest.ID = profileID
	profileRequest.Name = profileID

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, verifierHostURL+"/verifier/profile", "", //nolint: bodyclose
		"rw_token", bytes.NewBuffer(requestBytes))

	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated {
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	return nil
}

func (e *Steps) deleteVerifierProfile(profileID string) error {
	resp, err := bddutil.HTTPDo(http.MethodDelete, fmt.Sprintf(verifierHostURL+"/verifier/profile/%s", //nolint: bodyclose
		profileID), "", "rw_token", nil)
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

	return nil
}
