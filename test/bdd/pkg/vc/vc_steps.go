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
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/mr-tron/base58"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	"github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	"github.com/trustbloc/edge-service/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	expectedProfileResponseURI = "https://example.com/credentials"
	issuerURL                  = "http://localhost:8070/"
	verifierURL                = "http://localhost:8069/verifier"

	issueCredentialURLFormat = issuerURL + "%s" + "/credentials/issueCredential"
	serviceID                = "example"
	didMethodTrustBloc       = "did:trustbloc"
	didMethodSov             = "did:sov:danube "
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
	s.Step(`^Profile "([^"]*)" is created with DID "([^"]*)", privateKey "([^"]*)", signatureHolder "([^"]*)", uniRegistrar '([^']*)', didMethod "([^"]*)", signatureType "([^"]*)" and keyType "([^"]*)"$`, //nolint: lll
		e.createProfile)
	s.Step(`^We can retrieve profile "([^"]*)" with DID "([^"]*)" and signatureType "([^"]*)"$`, e.getProfile)
	s.Step(`^New verifiable credential is created from "([^"]*)" under "([^"]*)" profile$`, e.createCredential)
	s.Step(`^That credential is stored under "([^"]*)" profile$`, e.storeCreatedCredential)
	s.Step(`^Given "([^"]*)" is stored under "([^"]*)" profile$`, e.storeCredentialFromFile)
	s.Step(`^We can retrieve credential under "([^"]*)" profile$`, e.retrieveCredential)
	s.Step(`^Now we verify that credential for checks "([^"]*)" is "([^"]*)" with message "([^"]*)"$`,
		e.verifyCredential)
	s.Step(`^Now we verify that "([^"]*)" signed with "([^"]*)" presentation for checks "([^"]*)" is "([^"]*)" with message "([^"]*)"$`, //nolint: lll
		e.verifyPresentation)
	s.Step(`^Update created credential status "([^"]*)" and status reason "([^"]*)"$`, e.updateCredentialStatus)
	s.Step(`^"([^"]*)" has her "([^"]*)" issued as verifiable credential using "([^"]*)", "([^"]*)" and signatureType "([^"]*)"$`, //nolint: lll
		e.createProfileAndCredential)
	s.Step(`^"([^"]*)" has her "([^"]*)" issued as verifiable presentation using "([^"]*)", "([^"]*)" and signatureType "([^"]*)"$`, //nolint: lll
		e.createProfileAndPresentation)
}

func (e *Steps) verifyPresentation(holder, signatureType, checksList, result, respMessage string) error {
	vp, err := bddutil.CreatePresentation(e.bddContext.CreatedCredential, signatureType,
		getSignatureRepresentation(holder), e.bddContext.VDRI)
	if err != nil {
		return err
	}

	checks := strings.Split(checksList, ",")

	req := &operation.VerifyPresentationRequest{
		Presentation: vp,
		Opts: &operation.VerifyPresentationOptions{
			Checks: checks,
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := http.Post(verifierURL+"/presentations", "", //nolint: bodyclose
		bytes.NewBuffer(reqBytes))

	if err != nil {
		return err
	}

	return verify(resp, checks, result, respMessage)
}

func (e *Steps) createProfile(profileName, did, privateKey, holder, //nolint[:gocyclo,funlen]
	uniRegistrar, didMethod, signatureType, keyType string) error {
	template, ok := e.bddContext.TestData["profile_request_template.json"]
	if !ok {
		return fmt.Errorf("unable to find profile request template")
	}

	profileRequest := operation.ProfileRequest{}

	if err := json.Unmarshal(template, &profileRequest); err != nil {
		return err
	}

	var u operation.UNIRegistrar

	if uniRegistrar != "" {
		if err := json.Unmarshal([]byte(uniRegistrar), &u); err != nil {
			return err
		}
	}

	profileRequest.Name = profileName
	profileRequest.DID = did
	profileRequest.DIDPrivateKey = privateKey
	profileRequest.SignatureRepresentation = getSignatureRepresentation(holder)
	profileRequest.UNIRegistrar = u
	profileRequest.OverwriteIssuer = true
	profileRequest.SignatureType = signatureType
	profileRequest.DIDKeyType = keyType

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

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated {
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	profileResponse := profile.DataProfile{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	if errCheck := e.checkProfileResponse(profileName, didMethod, signatureType, &profileResponse); errCheck != nil {
		return errCheck
	}

	didDoc, err := bddutil.ResolveDID(e.bddContext.VDRI, profileResponse.DID, 10)
	if err != nil {
		return err
	}

	if err := validatePublicKey(didDoc, keyType); err != nil {
		return err
	}

	checkService := false

	if didMethod == didMethodTrustBloc || didMethod == didMethodSov {
		checkService = true
	}

	if checkService && len(didDoc.Service) != 1 {
		return fmt.Errorf("did doc service size not equal to 1")
	}

	if checkService && didDoc.Service[0].ID != didDoc.ID+"#"+serviceID {
		return fmt.Errorf("did doc service id %s not equal to %s", didDoc.Service[0].ID, didDoc.ID+"#"+serviceID)
	}

	return nil
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

func (e *Steps) getProfileData(profileName string) (*profile.DataProfile, error) {
	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Get(fmt.Sprintf(issuerURL+"profile/%s", profileName)) //nolint: bodyclose
	if err != nil {
		return nil, err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	profileResponse := &profile.DataProfile{}

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
	template, ok := e.bddContext.TestData[credential]
	if !ok {
		return fmt.Errorf("unable to find credential '%s' request template", credential)
	}

	cred, err := verifiable.NewUnverifiedCredential(template)
	if err != nil {
		return err
	}

	profileResponse, err := e.getProfileData(profileName)
	if err != nil {
		return fmt.Errorf("unable to fetch profile - %s", err)
	}

	cred.ID = profileResponse.URI + "/" + uuid.New().String()

	credBytes, err := cred.MarshalJSON()
	if err != nil {
		return err
	}

	req := &operation.IssueCredentialRequest{
		Credential: credBytes,
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, profileName)

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post(endpointURL, "", bytes.NewBuffer(requestBytes)) //nolint
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

	e.bddContext.CreatedCredential = respBytes

	return e.checkVC(respBytes, profileName)
}

func (e *Steps) createProfileAndCredential(user, credential, did, privateKey, signatureType string) error {
	profileName := fmt.Sprintf("%s_%s", strings.ToLower(user), uuid.New().String())

	err := e.createProfile(profileName, did, privateKey, "JWS", "", "", signatureType, "")
	if err != nil {
		return err
	}

	err = e.createCredential(credential, profileName)
	if err != nil {
		return err
	}

	e.bddContext.Args[bddutil.GetCredentialKey(user)] = string(e.bddContext.CreatedCredential)

	return nil
}

func (e *Steps) createProfileAndPresentation(user, credential, did, privateKey, signatureType string) error {
	profileName := fmt.Sprintf("%s_%s", strings.ToLower(user), uuid.New().String())

	err := e.createProfile(profileName, did, privateKey, "JWS", "", "", signatureType, "")
	if err != nil {
		return err
	}

	profileResponse, err := e.getProfileData(profileName)
	if err != nil {
		return err
	}

	err = e.createCredential(credential, profileName)
	if err != nil {
		return err
	}

	signingKey, err := base58.Decode(privateKey)
	if err != nil {
		return err
	}

	created := time.Now()
	signatureSuite := ed25519signature2018.New(suite.WithSigner(bddutil.GetSigner(signingKey)))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: getSignatureRepresentation("JWS"),
		Suite:                   signatureSuite,
		VerificationMethod:      profileResponse.Creator,
		Domain:                  "issuer.example.com",
		Challenge:               uuid.New().String(),
		Purpose:                 "authentication",
		Created:                 &created,
	}

	vp, err := bddutil.CreateCustomPresentation(e.bddContext.CreatedCredential, e.bddContext.VDRI, ldpContext)
	if err != nil {
		return err
	}

	e.bddContext.Args[bddutil.GetPresentationKey(user)] = string(vp)
	e.bddContext.Args[bddutil.GetOptionsKey(user)] = fmt.Sprintf(
		`{"challenge": "%s","domain": "%s","checks": ["proof"]}`, ldpContext.Challenge, ldpContext.Domain)

	return nil
}

func (e *Steps) storeCreatedCredential(profileName string) error {
	return e.storeCredential(profileName, e.bddContext.CreatedCredential)
}

func (e *Steps) storeCredentialFromFile(vcFile, profileName string) error {
	return e.storeCredential(profileName, e.bddContext.TestData[vcFile])
}

func (e *Steps) storeCredential(profileName string, vcBytes []byte) error {
	storeRequest := operation.StoreVCRequest{}

	storeRequest.Profile = profileName
	storeRequest.Credential = string(vcBytes)

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

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	e.bddContext.Args[profileName] = storeRequest.Credential

	return nil
}

func (e *Steps) retrieveCredential(profileName string) error {
	vcMap, err := getVCMap([]byte(e.bddContext.Args[profileName]))
	if err != nil {
		return fmt.Errorf("failed to get vc : %w", err)
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
		return fmt.Errorf("failed to make http request : %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response bytes : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	b, err := bddutil.AreEqualJSON([]byte(e.bddContext.Args[profileName]), respBytes)
	if err != nil {
		return fmt.Errorf("failed to validate of retrieved VC : %s", err.Error())
	}

	if !b {
		return fmt.Errorf("validation of retrieved VC failed")
	}

	return nil
}

func (e *Steps) verifyCredential(checksList, result, respMessage string) error {
	checks := strings.Split(checksList, ",")

	req := &operation.CredentialsVerificationRequest{
		Credential: e.bddContext.CreatedCredential,
		Opts: &operation.CredentialsVerificationOptions{
			Checks: checks,
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := http.Post(verifierURL+"/credentials", "", //nolint: bodyclose
		bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	return verify(resp, checks, result, respMessage)
}

func verify(resp *http.Response, checks []string, result, respMessage string) error {
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if result == "successful" {
		if resp.StatusCode != http.StatusOK {
			return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
		}

		verifiedResp := operation.CredentialsVerificationSuccessResponse{}

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

func (e *Steps) checkProfileResponse(expectedProfileResponseName, expectedProfileDID, expectedSignatureType string,
	profileResponse *profile.DataProfile) error {
	if profileResponse.Name != expectedProfileResponseName {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponseName, profileResponse.Name)
	}

	if expectedProfileDID != "" && !strings.Contains(profileResponse.DID, expectedProfileDID) {
		return fmt.Errorf("%s not containing %s", profileResponse.DID, expectedProfileDID)
	}

	if profileResponse.URI != expectedProfileResponseURI {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponseURI, profileResponse.URI)
	}

	if profileResponse.SignatureType != expectedSignatureType {
		return fmt.Errorf("expected %s but got %s instead",
			expectedSignatureType, profileResponse.SignatureType)
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
		return bddutil.ExpectedStringError(csl.CredentialStatusType, credentialStatusType)
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

func validatePublicKey(doc *ariesdid.Doc, keyType string) error {
	expectedJwkKeyType := ""

	switch keyType {
	case vccrypto.Ed25519KeyType:
		expectedJwkKeyType = "OKP"
	case vccrypto.P256KeyType:
		expectedJwkKeyType = "EC"
	}

	if strings.Contains(doc.ID, didMethodTrustBloc) {
		for _, v := range doc.PublicKey {
			if expectedJwkKeyType == v.JSONWebKey().Kty {
				return nil
			}
		}

		return fmt.Errorf("jwk key type : expected=%s", expectedJwkKeyType)
	}

	return nil
}
