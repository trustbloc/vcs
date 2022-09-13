/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	issuerURL              = "http://localhost:8075"
	issuerProfileURL       = issuerURL + "/issuer/profiles"
	issuerProfileURLFormat = issuerProfileURL + "/%s"

	updateCredentialStatusURLFormat = issuerProfileURLFormat + "/credentials/status"
	issueCredentialURLFormat        = issuerProfileURLFormat + "/credentials/issue"

	domain = "example.com"
)

func getProfileIDKey(profileName string) string {
	return profileName + "-profileID"
}

func getProfileAuthToken(profileName string) string {
	// temporary we use org id as token
	return profileName + "-userOrg"
}

func getProfile(profileName string) string {
	// temporary we use org id as token
	return profileName + "-profileObj"
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
	s.Step(`^V1 Profile "([^"]*)" for organization "([^"]*)" is created with signatureHolder "([^"]*)", didMethod "([^"]*)", signatureType "([^"]*)" and keyType "([^"]*)"$`, //nolint: lll
		e.createProfile)
	s.Step(`^V1 We can retrieve profile "([^"]*)" with DID "([^"]*)" and signatureType "([^"]*)"$`, e.getProfile)
	s.Step(`^V1 New verifiable credential is created from "([^"]*)" under "([^"]*)" profile$`, e.createCredential)
}

func (e *Steps) createProfile(profileName, organizationName, signatureHolder, didMethod, signatureType,
	keyType string) error {
	profileRequest := model.CreateIssuerProfileData{
		Name:           profileName,
		OidcConfig:     nil,
		OrganizationID: organizationName,
		Url:            issuerProfileURL,
		VcConfig: model.VCConfig{
			Contexts:                nil,
			DidMethod:               didMethod,
			Format:                  "ldp_vc",
			KeyType:                 keyType,
			SigningAlgorithm:        signatureType,
			SignatureRepresentation: signatureHolder,
			Status:                  nil,
		},
	}

	e.bddContext.Args[getProfileAuthToken(profileName)] = organizationName

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, issuerProfileURL, "application/json",
		e.bddContext.Args[getProfileAuthToken(profileName)], //nolint: bodyclose
		bytes.NewBuffer(requestBytes))
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	profileResponse := model.IssuerProfile{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	e.bddContext.Args[getProfileIDKey(profileName)] = profileResponse.Id

	if errCheck := e.checkProfileResponse(profileName, didMethod, signatureType, &profileResponse); errCheck != nil {
		return errCheck
	}

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, profileResponse.VcConfig.SigningDID, 10)
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) getProfileData(profileName string) (*model.IssuerProfile, error) {
	id := e.bddContext.Args[getProfileIDKey(profileName)]
	token := e.bddContext.Args[getProfileAuthToken(profileName)]

	resp, err := bddutil.HTTPDo(http.MethodGet, fmt.Sprintf(issuerProfileURLFormat, id), "", token, nil)
	if err != nil {
		return nil, err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	profileResponse := &model.IssuerProfile{}

	err = json.Unmarshal(respBytes, profileResponse)
	if err != nil {
		return nil, err
	}

	return profileResponse, nil
}

func (e *Steps) getProfile(profileName, did, signatureType string) error {
	profileResponse, err := e.getProfileData(profileName)
	if err != nil {
		return err
	}

	return e.checkProfileResponse(profileName, did, signatureType, profileResponse)
}

func (e *Steps) createCredential(credential, profileName string) error {
	token := e.bddContext.Args[getProfileAuthToken(profileName)]

	template, ok := e.bddContext.TestData[credential]
	if !ok {
		return fmt.Errorf("unable to find credential '%s' request template", credential)
	}

	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	cred, err := verifiable.ParseCredential(template, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	profileResponse, err := e.getProfileData(profileName)
	if err != nil {
		return fmt.Errorf("unable to fetch profile - %w", err)
	}

	cred.ID = profileResponse.Url + "/" + uuid.New().String()

	req := &model.IssueCredentialData{
		Credential: cred,
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, profileResponse.Id)

	resp, err := bddutil.HTTPDo(http.MethodPost, endpointURL, "application/json", token, //nolint: bodyclose
		bytes.NewBuffer(requestBytes))
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

	e.bddContext.CreatedCredential = respBytes

	return e.checkVC(respBytes, profileName)
}

func (e *Steps) checkProfileResponse(expectedProfileResponseName, expectedProfileDIDMethod, expectedSignatureType string,
	profileResponse *model.IssuerProfile) error {
	if profileResponse.Name != expectedProfileResponseName {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponseName, profileResponse.Name)
	}

	if expectedProfileDIDMethod != "" &&
		!strings.Contains(profileResponse.VcConfig.SigningDID, expectedProfileDIDMethod) {
		return fmt.Errorf("%s not containing %s", profileResponse.VcConfig.SigningDID, expectedProfileDIDMethod)
	}

	fullIssuerProfileURL := fmt.Sprintf(issuerProfileURLFormat, //nolint: bodyclose
		profileResponse.Id)

	if profileResponse.Url != fullIssuerProfileURL {
		return fmt.Errorf("expected %s but got %s instead", fullIssuerProfileURL,
			profileResponse.Url)
	}

	if profileResponse.VcConfig.SigningAlgorithm != expectedSignatureType {
		return fmt.Errorf("expected %s but got %s instead",
			expectedSignatureType, profileResponse.VcConfig.SigningAlgorithm)
	}

	e.bddContext.CreatedProfileV1 = profileResponse

	return nil
}

func (e *Steps) checkVC(vcBytes []byte, profileName string) error {
	vcMap, err := getVCMap(vcBytes)
	if err != nil {
		return err
	}

	err = checkCredentialStatusType(vcMap, csl.StatusList2021Entry)
	if err != nil {
		return err
	}

	err = checkIssuer(vcMap, profileName)
	if err != nil {
		return err
	}

	return e.checkSignatureHolder(vcMap)
}

func (e *Steps) checkSignatureHolder(vcMap map[string]interface{}) error {
	proof, found := vcMap["proof"]
	if !found {
		return fmt.Errorf("unable to find proof in VC map")
	}

	proofMap, ok := proof.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unable to assert proof field type as map[string]interface{}")
	}

	switch e.bddContext.CreatedProfileV1.VcConfig.SignatureRepresentation {
	case "JWS":
		_, found := proofMap["jws"]
		if !found {
			return fmt.Errorf("unable to find jws in proof")
		}
	case "ProofValue":
		_, found := proofMap["proofValue"]
		if !found {
			return fmt.Errorf("unable to find proofValue in proof")
		}
	default:
		return fmt.Errorf("unexpected signature representation in profile")
	}

	return nil
}

func checkCredentialStatusType(vcMap map[string]interface{}, expected string) error {
	credentialStatusType, err := getCredentialStatusType(vcMap)
	if err != nil {
		return err
	}

	if credentialStatusType != expected {
		return bddutil.ExpectedStringError(csl.StatusList2021Entry, credentialStatusType)
	}

	return nil
}

func checkIssuer(vcMap map[string]interface{}, expected string) error {
	issuer, found := vcMap["issuer"]
	if !found {
		return fmt.Errorf("unable to find issuer in VC map")
	}

	issuerMap, ok := issuer.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unable to assert issuer field type as map[string]interface{}")
	}

	issuerName, found := issuerMap["name"]
	if !found {
		return fmt.Errorf("unable to find issuer name in VC map")
	}

	issuerNameStr, ok := issuerName.(string)
	if !ok {
		return fmt.Errorf("unable to assert issuer name type as string")
	}

	if issuerNameStr != expected {
		return bddutil.ExpectedStringError(expected, issuerNameStr)
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
