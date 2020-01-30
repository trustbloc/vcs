/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/DATA-DOG/godog"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
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
	s.Step(`^Send request to create a profile with profile request "([^"]*)"`+
		` and receive the profile response "([^"]*)"$`, e.createProfile)
	s.Step(`^Send request to get a profile with id "([^"]*)" and receive the profile response "([^"]*)"$`, e.getProfile)
	s.Step(`^Send request to create a credential with credential request "([^"]*)"`+
		` and receive a verified credential with issuer ID "([^"]*)" and issuer name "([^"]*)"$`, e.createCredential)
	s.Step(`^Send request to store a credential with StoreVCRequest "([^"]*)"$`, e.storeCredential)
	s.Step(`^Send request to retrieve a credential with id "([^"]*)"`+
		` under profile "([^"]*)" and receive VC with issuer ID "([^"]*)" and issuer name "([^"]*)"$`, e.retrieveCredential)
	s.Step(`^Verify the credential "([^"]*)"$`, e.verifyCredential)
}

func (e *Steps) createProfile(profileRequestArgKey, expectedProfileResponseArgkey string) error {
	profileRequestJSON := e.bddContext.Args[profileRequestArgKey]

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post("http://localhost:8070/profile", "", //nolint: bodyclose
		bytes.NewBuffer([]byte(profileRequestJSON)))
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected status code %d, received %d", http.StatusCreated, resp.StatusCode)
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	profileResponse := operation.ProfileResponse{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	return e.checkProfileResponse(expectedProfileResponseArgkey, &profileResponse)
}

func (e *Steps) getProfile(profileID, expectedProfileResponseArgkey string) error {
	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Get(fmt.Sprintf("http://localhost:8070/profile/%s", profileID)) //nolint: bodyclose
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	profileResponse := operation.ProfileResponse{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	return e.checkProfileResponse(expectedProfileResponseArgkey, &profileResponse)
}

func (e *Steps) createCredential(credentialRequestArgKey, expectedIssuerID, expectedIssuerName string) error {
	credentialRequest := e.bddContext.Args[credentialRequestArgKey]

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post("http://localhost:8070/credential", "", //nolint: bodyclose
		bytes.NewBuffer([]byte(credentialRequest)))
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected status code %d, received %d", http.StatusCreated, resp.StatusCode)
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	vc := verifiable.Credential{}

	err = json.Unmarshal(respBytes, &vc)
	if err != nil {
		return err
	}

	if vc.Issuer.ID != expectedIssuerID {
		return fmt.Errorf("expected %s but got %s instead", expectedIssuerID, vc.Issuer.ID)
	}

	if vc.Issuer.Name != expectedIssuerName {
		return fmt.Errorf("expected %s but got %s instead", expectedIssuerName, vc.Issuer.Name)
	}

	return nil
}

func (e *Steps) storeCredential(storeVCRequestArgKey string) error {
	createCredentialResponse := e.bddContext.Args[storeVCRequestArgKey]

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post("http://localhost:8070/store", "", //nolint: bodyclose
		bytes.NewBuffer([]byte(createCredentialResponse)))
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d, received %d", http.StatusOK, resp.StatusCode)
	}

	return nil
}

func (e *Steps) retrieveCredential(credentialID, profileName, expectedIssuerID, expectedIssuerName string) error {
	escapedCredentialID := url.PathEscape(credentialID)
	escapedProfileName := url.PathEscape(profileName)

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Get("http://localhost:8070/retrieve?id=" + escapedCredentialID + //nolint: bodyclose
		"&profile=" + escapedProfileName)
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d, received %d", http.StatusOK, resp.StatusCode)
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	response := verifiable.Credential{}

	err = json.Unmarshal(respBytes, &response)
	if err != nil {
		return err
	}

	if response.Issuer.ID != expectedIssuerID {
		return fmt.Errorf("expected %s but got %s instead", expectedIssuerID, response.Issuer.ID)
	}

	if response.Issuer.Name != expectedIssuerName {
		return fmt.Errorf("expected %s but got %s instead", expectedIssuerName, response.Issuer.Name)
	}

	return nil
}

func (e *Steps) verifyCredential(validVCArgKey string) error {
	validVC := e.bddContext.Args[validVCArgKey]

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post("http://localhost:8070/verify", "", //nolint: bodyclose
		bytes.NewBuffer([]byte(validVC)))
	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d, received %d", http.StatusOK, resp.StatusCode)
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	verifiedResp := operation.VerifyCredentialResponse{}

	err = json.Unmarshal(respBytes, &verifiedResp)
	if err != nil {
		return err
	}

	if !verifiedResp.Verified {
		return fmt.Errorf("the VC server says that the provided VC isn't valid")
	}

	if verifiedResp.Message != "success" {
		return fmt.Errorf("expected %s but got %s instead", "success", verifiedResp.Message)
	}

	return nil
}

func (e *Steps) checkProfileResponse(expectedProfileResponseArgkey string,
	profileResponse *operation.ProfileResponse) error {
	expectedProfileResponse := operation.ProfileResponse{}

	err := json.Unmarshal([]byte(e.bddContext.Args[expectedProfileResponseArgkey]), &expectedProfileResponse)
	if err != nil {
		return err
	}

	if profileResponse.Name != expectedProfileResponse.Name {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponse.Name, profileResponse.Name)
	}

	if profileResponse.DID != expectedProfileResponse.DID {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponse.DID, profileResponse.DID)
	}

	if profileResponse.URI != expectedProfileResponse.URI {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponse.URI, profileResponse.URI)
	}

	if profileResponse.SignatureType != expectedProfileResponse.SignatureType {
		return fmt.Errorf("expected %s but got %s instead",
			expectedProfileResponse.SignatureType, profileResponse.SignatureType)
	}

	if profileResponse.Creator != expectedProfileResponse.Creator {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponse.Creator, profileResponse.Creator)
	}

	if profileResponse.Created == nil {
		return fmt.Errorf("profile response created field was unexpectedly nil")
	}

	return nil
}

func closeReadCloser(respBody io.ReadCloser) {
	err := respBody.Close()
	if err != nil {
		log.Errorf("Failed to close response body: %s", err.Error())
	}
}
