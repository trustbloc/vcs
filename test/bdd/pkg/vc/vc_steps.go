/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	expectedProfileDID                   = "did:trustbloc"
	expectedProfileResponseURI           = "https://example.com/credentials"
	expectedProfileResponseSignatureType = "Ed25519Signature2018"
	issuerURL                            = "http://localhost:8070/"
	verifierURL                          = "http://localhost:8069/"
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
	s.Step(`^Profile "([^"]*)" is created with DID "([^"]*)", privateKey "([^"]*)" and signatureHolder "([^"]*)"$`,
		e.createProfile)
	s.Step(`^We can retrieve profile "([^"]*)" with DID "([^"]*)"$`, e.getProfile)
	s.Step(`^New credential is created under "([^"]*)" profile$`, e.createCredential)
	s.Step(`^That credential is stored under "([^"]*)" profile$`, e.storeCredential)
	s.Step(`^We can retrieve credential under "([^"]*)" profile$`, e.retrieveCredential)
	s.Step(`^Now we verify that credential with verified flag is "([^"]*)" and verified msg contains "([^"]*)"$`,
		e.verifyCredential)
	s.Step(`^Now we verify that "([^"]*)" signed presentation with verified flag is "([^"]*)" and verified msg contains "([^"]*)"$`, //nolint: lll
		e.verifyPresentation)
	s.Step(`^Update created credential status "([^"]*)" and status reason "([^"]*)"$`, e.updateCredentialStatus)
}

func getSigner(privKey []byte) *signer {
	return &signer{privateKey: privKey}
}

type signer struct {
	privateKey []byte
}

func (s *signer) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}

func (e *Steps) verifyPresentation(holder, verifiedFlag, verifiedMsg string) error {
	vp, err := e.createPresentation(e.bddContext.CreatedCredential, getSignatureRepresentation(holder))
	if err != nil {
		return err
	}

	resp, err := http.Post(verifierURL+"verifyPresentation", "", //nolint: bodyclose
		bytes.NewBuffer(vp))

	if err != nil {
		return err
	}

	return verify(resp, verifiedFlag, verifiedMsg)
}

func (e *Steps) createPresentation(vcBytes []byte, representation verifiable.SignatureRepresentation) ([]byte, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: representation,
		Suite:                   ed25519signature2018.New(ed25519signature2018.WithSigner(getSigner(privateKey))),
	}

	// parse vc
	vc, _, err := verifiable.NewCredential(vcBytes,
		verifiable.WithEmbeddedSignatureSuites(ed25519signature2018.New()),
		verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(e.bddContext.VDRI).PublicKeyFetcher()))
	if err != nil {
		return nil, err
	}

	// create verifiable presentation from vc
	vp, err := vc.Presentation()
	if err != nil {
		return nil, err
	}

	// add linked data proof
	err = vp.AddLinkedDataProof(ldpContext)
	if err != nil {
		return nil, err
	}

	return json.Marshal(vp)
}

func (e *Steps) createProfile(profileName, did, privateKey, holder string) error {
	profileRequest := operation.ProfileRequest{}

	err := json.Unmarshal(e.bddContext.ProfileRequestTemplate, &profileRequest)
	if err != nil {
		return err
	}

	profileRequest.Name = profileName
	profileRequest.DID = did
	profileRequest.DIDPrivateKey = privateKey
	profileRequest.SignatureRepresentation = getSignatureRepresentation(holder)

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post(issuerURL+"profile", "", //nolint: bodyclose
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

	profileDID := expectedProfileDID

	if profileRequest.DID != "" {
		profileDID = profileRequest.DID
	}

	if err := e.checkProfileResponse(profileName, profileDID, &profileResponse); err != nil {
		return err
	}

	return resolveDID(e.bddContext.VDRI, profileResponse.DID, 10)
}

func getSignatureRepresentation(holder string) verifiable.SignatureRepresentation {
	switch holder {
	case "JWS":
		return verifiable.SignatureJWS
	case "ProofValue":
		return verifiable.SignatureProofValue
	default:
		return verifiable.SignatureJWS
	}
}

func (e *Steps) getProfile(profileName, did string) error {
	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Get(fmt.Sprintf(issuerURL+"profile/%s", profileName)) //nolint: bodyclose
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

	profileDID := expectedProfileDID

	if did != "" {
		profileDID = did
	}

	return e.checkProfileResponse(profileName, profileDID, &profileResponse)
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
	resp, err := http.Post(issuerURL+"credential", "", //nolint: bodyclose
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

	return e.checkVC(respBytes, profileName)
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
	resp, err := http.Post(issuerURL+"store", "", //nolint: bodyclose
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
	resp, err := http.Get(issuerURL + "retrieve?id=" + escapedCredentialID + //nolint: bodyclose
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

	// For some reason there's an extra line at the end of the credential returned from the create credential handler.
	// By compacting the JSON we can remove it, allowing us to directly compare them as strings.
	// TODO: Figure out why and fix it: https://github.com/trustbloc/edge-service/issues/104
	buffer := new(bytes.Buffer)

	err = json.Compact(buffer, e.bddContext.CreatedCredential)
	if err != nil {
		return err
	}

	expectedCredential := buffer.String()

	receivedCredential := string(respBytes)

	if receivedCredential != expectedCredential {
		return expectedStringError(expectedCredential, receivedCredential)
	}

	return nil
}

func (e *Steps) verifyCredential(verifiedFlag, verifiedMsg string) error {
	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post(verifierURL+"verify", "", //nolint: bodyclose
		bytes.NewBuffer(e.bddContext.CreatedCredential))
	if err != nil {
		return err
	}

	return verify(resp, verifiedFlag, verifiedMsg)
}

func verify(resp *http.Response, verifiedFlag, verifiedMsg string) error {
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

	if strconv.FormatBool(verifiedResp.Verified) != verifiedFlag {
		return fmt.Errorf("resp verified %t not equal verified flag %s", verifiedResp.Verified, verifiedFlag)
	}

	if !strings.Contains(verifiedResp.Message, verifiedMsg) {
		return fmt.Errorf("resp verified msg %s not contains %s", verifiedResp.Message, verifiedMsg)
	}

	return nil
}

func (e *Steps) updateCredentialStatus(status, statusReason string) error {
	storeRequest := operation.UpdateCredentialStatusRequest{}

	storeRequest.Status = status
	storeRequest.StatusReason = statusReason
	storeRequest.Credential = string(e.bddContext.CreatedCredential)

	requestBytes, err := json.Marshal(storeRequest)
	if err != nil {
		return err
	}

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post(issuerURL+"updateStatus", "", //nolint: bodyclose
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

func (e *Steps) checkProfileResponse(expectedProfileResponseName, expectedProfileDID string,
	profileResponse *profile.DataProfile) error {
	if profileResponse.Name != expectedProfileResponseName {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponseName, profileResponse.Name)
	}

	if !strings.Contains(profileResponse.DID, expectedProfileDID) {
		return fmt.Errorf("%s not containing %s", profileResponse.DID, expectedProfileDID)
	}

	if profileResponse.URI != expectedProfileResponseURI {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponseURI, profileResponse.URI)
	}

	if profileResponse.SignatureType != expectedProfileResponseSignatureType {
		return fmt.Errorf("expected %s but got %s instead",
			expectedProfileResponseSignatureType, profileResponse.SignatureType)
	}

	// The created field depends on the current time, so let's just made sure it's not nil
	if profileResponse.Created == nil {
		return fmt.Errorf("profile response created field was unexpectedly nil")
	}

	e.bddContext.CreatedProfile = profileResponse

	return nil
}

func (e *Steps) checkVC(vcBytes []byte, profileName string) error {
	vcMap, err := getVCMap(vcBytes)
	if err != nil {
		return err
	}

	err = checkCredentialStatusType(vcMap, csl.CredentialStatusType)
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

	switch e.bddContext.CreatedProfile.SignatureRepresentation {
	case verifiable.SignatureJWS:
		_, found := proofMap["jws"]
		if !found {
			return fmt.Errorf("unable to find jws in proof")
		}
	case verifiable.SignatureProofValue:
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
		return expectedStringError(csl.CredentialStatusType, credentialStatusType)
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
		return expectedStringError(expected, issuerNameStr)
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
