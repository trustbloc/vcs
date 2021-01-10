/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package governance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cucumber/godog"

	"github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	governanceops "github.com/trustbloc/edge-service/pkg/restapi/governance/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
	"github.com/trustbloc/edge-service/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	governanceURL   = "http://localhost:8066"
	assertionMethod = "assertionMethod"
	did             = "did:test:123"
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
	s.Step(`^Governance Profile "([^"]*)" is created with DID "([^"]*)", privateKey "([^"]*)", keyID "([^"]*)", signatureHolder "([^"]*)", uniRegistrar '([^']*)', didMethod "([^"]*)", signatureType "([^"]*)" and keyType "([^"]*)"$`, // nolint
		e.createGovernanceProfile)
	s.Step(`^Governance "([^"]*)" generates credential with signatureType "([^"]*)"$`, e.issueGovernanceVC)
}

func (e *Steps) issueGovernanceVC(profileName, signatureType string) error {
	issueCredRequest := governanceops.IssueCredentialRequest{DID: did}
	requestBytes, err := json.Marshal(issueCredRequest)

	if err != nil {
		return err
	}

	url := governanceURL + "/governance/" + profileName + "/issueCredential"

	resp, err := bddutil.HTTPDo(http.MethodPost, url, "", //nolint: bodyclose
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

	return e.verifyCredential(respBytes, signatureType, assertionMethod)
}

//nolint:funlen,gocyclo
func (e *Steps) verifyCredential(signedVCByte []byte, signatureType, purpose string) error {
	signedVCResp := make(map[string]interface{})

	err := json.Unmarshal(signedVCByte, &signedVCResp)
	if err != nil {
		return err
	}

	err = checkCredentialStatusType(signedVCResp, csl.RevocationList2020Status)
	if err != nil {
		return err
	}

	proof, ok := signedVCResp["proof"].(map[string]interface{})
	if !ok {
		return errors.New("unable to convert proof to a map")
	}

	if proof["type"] != signatureType {
		return errors.New("proof type is not valid")
	}

	if proof["jws"] == "" {
		return errors.New("proof jws value is empty")
	}

	proofPurpose, ok := proof["proofPurpose"]
	if !ok {
		return fmt.Errorf("proof purpose not found")
	}

	proofPurposeStr, ok := proofPurpose.(string)
	if !ok {
		return fmt.Errorf("proof purpose not a string")
	}

	if proofPurposeStr != purpose {
		return bddutil.ExpectedStringError(purpose, proofPurposeStr)
	}

	credentialSubject, ok := signedVCResp["credentialSubject"].(map[string]interface{})
	if !ok {
		return errors.New("unable to convert credentialSubject to a map")
	}

	if credentialSubject["name"] == "" {
		return errors.New("credentialSubject name value is empty")
	}

	define, ok := credentialSubject["define"].([]interface{})
	if !ok {
		return errors.New("unable to convert define to a array")
	}

	defineData, ok := define[0].(map[string]interface{})
	if !ok {
		return errors.New("unable to convert credentialSubject to a map")
	}

	if defineData["name"] != "DID" {
		return errors.New("define name value is not equal to DID")
	}

	if defineData["id"] != did {
		return fmt.Errorf("define id value is not equal to %s", did)
	}

	return nil
}

//nolint:funlen
func (e *Steps) createGovernanceProfile(profileName, did, privateKey, keyID, signatureRep, uniRegistrar,
	didMethod, signatureType, keyType string) error {
	profileRequest := governanceops.GovernanceProfileRequest{}

	var u model.UNIRegistrar

	if uniRegistrar != "" {
		if err := json.Unmarshal([]byte(uniRegistrar), &u); err != nil {
			return err
		}
	}

	profileRequest.Name = profileName
	profileRequest.DID = did
	profileRequest.DIDPrivateKey = privateKey
	profileRequest.SignatureRepresentation = bddutil.GetSignatureRepresentation(signatureRep)
	profileRequest.UNIRegistrar = u
	profileRequest.SignatureType = signatureType
	profileRequest.DIDKeyType = keyType
	profileRequest.DIDKeyID = keyID

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, governanceURL+"/governance/profile", "", "rw_token", //nolint: bodyclose
		bytes.NewBuffer(requestBytes))

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

	profileResponse := profile.GovernanceProfile{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	if errCheck := e.checkProfileResponse(profileName, didMethod, signatureType, &profileResponse); errCheck != nil {
		return errCheck
	}

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, profileResponse.DID, 10)
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) checkProfileResponse(expectedProfileResponseName, expectedProfileDID, expectedSignatureType string,
	profileResponse *profile.GovernanceProfile) error {
	if profileResponse.Name != expectedProfileResponseName {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponseName, profileResponse.Name)
	}

	if expectedProfileDID != "" && !strings.Contains(profileResponse.DID, expectedProfileDID) {
		return fmt.Errorf("%s not containing %s", profileResponse.DID, expectedProfileDID)
	}

	if profileResponse.SignatureType != expectedSignatureType {
		return fmt.Errorf("expected %s but got %s instead",
			expectedSignatureType, profileResponse.SignatureType)
	}

	// The created field depends on the current time, so let's just made sure it's not nil
	if profileResponse.Created == nil {
		return fmt.Errorf("profile response created field was unexpectedly nil")
	}

	return nil
}

func checkCredentialStatusType(vcMap map[string]interface{}, expected string) error {
	credentialStatusType, err := getCredentialStatusType(vcMap)
	if err != nil {
		return err
	}

	if credentialStatusType != expected {
		return bddutil.ExpectedStringError(csl.RevocationList2020Status, credentialStatusType)
	}

	return nil
}

func getCredentialStatusType(vcMap map[string]interface{}) (string, error) {
	credentialStatus, found := vcMap["credentialStatus"]
	if !found {
		return "nil", fmt.Errorf("unable to find credentialStatus in VC map")
	}

	credentialStatusMap, ok := credentialStatus.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unable to assert credentialStatus field type as map[string]interface{}")
	}

	credentialStatusType, found := credentialStatusMap["type"]
	if !found {
		return "", fmt.Errorf("unable to find credentialStatus type in VC map")
	}

	return credentialStatusType.(string), nil
}
