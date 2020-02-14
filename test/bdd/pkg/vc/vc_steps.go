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
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	expectedProfileResponseDIDAndIssuerID = "did:sidetree"
	expectedProfileResponseURI            = "https://example.com/credentials"
	expectedProfileResponseSignatureType  = "Ed25519Signature2018"
	expectedProfileResponseCreator        = "#key-1"
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
	s.Step(`^Profile "([^"]*)" is created$`, e.createProfile)
	s.Step(`^We can retrieve profile "([^"]*)"$`, e.getProfile)
	s.Step(`^New credential is created under "([^"]*)" profile$`, e.createCredential)
	s.Step(`^That credential is stored under "([^"]*)" profile$`, e.storeCredential)
	s.Step(`^We can retrieve credential under "([^"]*)" profile$`, e.retrieveCredential)
	s.Step(`^Now we verify that credential$`, e.verifyCredential)
}

func (e *Steps) createProfile(profileName string) error {
	profileRequest := operation.ProfileRequest{}

	err := json.Unmarshal(e.bddContext.ProfileRequestTemplate, &profileRequest)
	if err != nil {
		return err
	}

	profileRequest.Name = profileName

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post("http://localhost:8070/profile", "", //nolint: bodyclose
		bytes.NewBuffer(requestBytes))
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated {
		return expectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	profileResponse := profile.DataProfile{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	if err := e.checkProfileResponse(profileName, &profileResponse); err != nil {
		return err
	}

	return resolveDID(e.bddContext.VDRI, profileResponse.DID, 10)
}

func (e *Steps) getProfile(profileName string) error {
	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Get(fmt.Sprintf("http://localhost:8070/profile/%s", profileName)) //nolint: bodyclose
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	profileResponse := profile.DataProfile{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	return e.checkProfileResponse(profileName, &profileResponse)
}

func (e *Steps) createCredential(profileName string) error {
	credentialRequest := operation.CreateCredentialRequest{}

	err := json.Unmarshal(e.bddContext.CreateCredentialRequestTemplate, &credentialRequest)
	if err != nil {
		return err
	}

	credentialRequest.Profile = profileName

	requestBytes, err := json.Marshal(credentialRequest)
	if err != nil {
		return err
	}

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post("http://localhost:8070/credential", "", //nolint: bodyclose
		bytes.NewBuffer(requestBytes))
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated {
		return expectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	e.bddContext.CreatedCredential = respBytes

	return checkVC(respBytes, profileName)
}

func (e *Steps) storeCredential(profileName string) error {
	storeRequest := operation.StoreVCRequest{}

	storeRequest.Profile = profileName
	storeRequest.Credential = string(e.bddContext.CreatedCredential)

	requestBytes, err := json.Marshal(storeRequest)
	if err != nil {
		return err
	}

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post("http://localhost:8070/store", "", //nolint: bodyclose
		bytes.NewBuffer(requestBytes))
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return expectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	return nil
}

func (e *Steps) retrieveCredential(profileName string) error {
	vcMap, err := getVCMap(e.bddContext.CreatedCredential)
	if err != nil {
		return err
	}

	vcID, found := vcMap["id"]
	if !found {
		return fmt.Errorf("unable to find ID in VC map")
	}

	vcIDString, ok := vcID.(string)
	if !ok {
		return fmt.Errorf("unable to assert vc ID field type as string")
	}

	escapedCredentialID := url.PathEscape(vcIDString)
	escapedProfileName := url.PathEscape(profileName)

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Get("http://localhost:8070/retrieve?id=" + escapedCredentialID + //nolint: bodyclose
		"&profile=" + escapedProfileName)
	if err != nil {
		return err
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return expectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	unescapedResponse, err := strconv.Unquote(string(respBytes))
	if err != nil {
		return err
	}

	expectedCredential := string(e.bddContext.CreatedCredential)
	if unescapedResponse != expectedCredential {
		return expectedStringError(expectedCredential, unescapedResponse)
	}

	return nil
}

func (e *Steps) verifyCredential() error {
	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post("http://localhost:8070/verify", "", //nolint: bodyclose
		bytes.NewBuffer(e.bddContext.CreatedCredential))
	if err != nil {
		return err
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return expectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
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
		return expectedStringError("success", verifiedResp.Message)
	}

	return nil
}

func (e *Steps) checkProfileResponse(expectedProfileResponseName string,
	profileResponse *profile.DataProfile) error {
	if profileResponse.Name != expectedProfileResponseName {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponseName, profileResponse.Name)
	}

	if !strings.Contains(profileResponse.DID, expectedProfileResponseDIDAndIssuerID) {
		return fmt.Errorf("%s not containing %s", profileResponse.DID, expectedProfileResponseDIDAndIssuerID)
	}

	if profileResponse.URI != expectedProfileResponseURI {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponseURI, profileResponse.URI)
	}

	if profileResponse.SignatureType != expectedProfileResponseSignatureType {
		return fmt.Errorf("expected %s but got %s instead",
			expectedProfileResponseSignatureType, profileResponse.SignatureType)
	}

	if !strings.Contains(profileResponse.Creator, expectedProfileResponseCreator) {
		return fmt.Errorf("%s not containing %s", profileResponse.Creator, expectedProfileResponseCreator)
	}

	// The created field depends on the current time, so let's just made sure it's not nil
	if profileResponse.Created == nil {
		return fmt.Errorf("profile response created field was unexpectedly nil")
	}

	return nil
}

func checkVC(vcBytes []byte, profileName string) error {
	issuerID, issuerName, err := getVCFieldsToCheck(vcBytes)
	if err != nil {
		return err
	}

	return checkVCFields(issuerID, issuerName, profileName)
}

func getVCFieldsToCheck(vcBytes []byte) (string, string, error) {
	vcMap, err := getVCMap(vcBytes)
	if err != nil {
		return "", "", err
	}

	issuer, found := vcMap["issuer"]
	if !found {
		return "", "", fmt.Errorf("unable to find issuer in VC map")
	}

	issuerMap, ok := issuer.(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("unable to assert issuer field type as map[string]interface{}")
	}

	issuerID, found := issuerMap["id"]
	if !found {
		return "", "", fmt.Errorf("unable to find issuer ID in VC map")
	}

	issuerIDString, ok := issuerID.(string)
	if !ok {
		return "", "", fmt.Errorf("unable to assert issuer ID type as string")
	}

	issuerName, found := issuerMap["name"]
	if !found {
		return "", "", fmt.Errorf("unable to find issuer name in VC map")
	}

	issuerNameString, ok := issuerName.(string)
	if !ok {
		return "", "", fmt.Errorf("unable to assert issuer name type as string")
	}

	return issuerIDString, issuerNameString, nil
}

func checkVCFields(issuerID, issuerName, profileName string) error {
	if !strings.Contains(issuerID, expectedProfileResponseDIDAndIssuerID) {
		return fmt.Errorf("%s not containing %s", issuerID, expectedProfileResponseDIDAndIssuerID)
	}

	if issuerName != profileName {
		return expectedStringError(profileName, issuerName)
	}

	return nil
}

func getVCMap(vcBytes []byte) (map[string]interface{}, error) {
	// Can't fully unmarshall the vc using verifiable.NewCredential since we don't have the key.
	// As a workaround we can unmarshal to a map[string]interface{}
	var vcMap map[string]interface{}

	err := json.Unmarshal(vcBytes, &vcMap)
	if err != nil {
		return nil, err
	}

	return vcMap, nil
}

func expectedStringError(expected, actual string) error {
	return fmt.Errorf("expected %s but got %s instead", expected, actual)
}

func expectedStatusCodeError(expected, actual int, respBytes []byte) error {
	return fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
		expected, actual, respBytes)
}

func closeReadCloser(respBody io.ReadCloser) {
	err := respBody.Close()
	if err != nil {
		log.Errorf("Failed to close response body: %s", err.Error())
	}
}

func resolveDID(vdriRegistry vdriapi.Registry, did string, maxRetry int) error {
	var err error
	for i := 1; i <= maxRetry; i++ {
		_, err = vdriRegistry.Resolve(did)
		if err == nil || !strings.Contains(err.Error(), "DID does not exist") {
			return err
		}

		time.Sleep(1 * time.Second)
	}

	return err
}
