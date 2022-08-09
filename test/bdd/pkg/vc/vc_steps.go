/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	vcsstorage "github.com/trustbloc/vcs/pkg/storage"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	holderops "github.com/trustbloc/vcs/pkg/restapi/holder/operation"
	"github.com/trustbloc/vcs/pkg/restapi/issuer/operation"
	verifierops "github.com/trustbloc/vcs/pkg/restapi/verifier/operation"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	expectedProfileResponseURI = "https://example.com/credentials"
	issuerURL                  = "http://localhost:8070/"
	verifierURL                = "http://localhost:8069"
	holderURL                  = "http://localhost:8067"

	updateCredentialStatusURLFormat = issuerURL + "%s" + "/credentials/status"
	issueCredentialURLFormat        = issuerURL + "%s" + "/credentials/issue"
	signPresentationURLFormat       = holderURL + "/%s" + "/prove/presentations"
	verifyCredentialURLFormat       = verifierURL + "/%s" + "/verifier/credentials/verify"
	verifyPresentationURLFormat     = verifierURL + "/%s" + "/verifier/presentations/verify"

	domain = "example.com"
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
func (e *Steps) RegisterSteps(s *godog.ScenarioContext) {
	s.Step(`^Profile "([^"]*)" is created with DID "([^"]*)", privateKey "([^"]*)", keyID "([^"]*)", signatureHolder "([^"]*)", didMethod "([^"]*)", signatureType "([^"]*)" and keyType "([^"]*)"$`, //nolint: lll
		e.createProfile)
	s.Step(`^We can retrieve profile "([^"]*)" with DID "([^"]*)" and signatureType "([^"]*)"$`, e.getProfile)
	s.Step(`^New verifiable credential is created from "([^"]*)" under "([^"]*)" profile$`, e.createCredential)
	s.Step(`^That credential is stored under "([^"]*)" profile$`, e.storeCreatedCredential)
	s.Step(`^Given "([^"]*)" is stored under "([^"]*)" profile$`, e.createProfileAndStoreCredentialFromFile)
	s.Step(`^We can retrieve credential under "([^"]*)" profile$`, e.retrieveCredential)
	s.Step(`^Now we verify that credential for checks "([^"]*)" is "([^"]*)" with message "([^"]*)"$`,
		e.verifyCredential)
	s.Step(`^Now we verify that "([^"]*)" signed with "([^"]*)" presentation for checks "([^"]*)" is "([^"]*)" with message "([^"]*)"$`, //nolint: lll
		e.signAndVerifyPresentation)
	s.Step(`^Revoke created credential status$`, e.revokeCredential)
	s.Step(`^"([^"]*)" has her "([^"]*)" issued as verifiable credential using "([^"]*)", "([^"]*)", "([^"]*)", signatureType "([^"]*)" and keyType "([^"]*)"$`, //nolint: lll
		e.createProfileAndCredential)
	s.Step(`^"([^"]*)" has her "([^"]*)" issued as verifiable presentation using "([^"]*)", "([^"]*)", "([^"]*)", signatureType "([^"]*)" and keyType "([^"]*)"$`, //nolint: lll
		e.createProfileAndPresentation)

	// CHAPI
	s.Step(`^"([^"]*)" has a profile with signature type "([^"]*)" and DID key type "([^"]*)" created with the Issuer HTTP Service$`, //nolint: lll
		e.createBasicIssuerProfile)
	s.Step(`^"([^"]*)" sends DIDAuth request to "([^"]*)" for authentication$`, e.createAndSendDIDAuthRequest)
	s.Step(`^"([^"]*)" issues the education degree to "([^"]*)"$`, e.issueCredential)
	s.Step(`^"([^"]*)" issues the "([^"]*)" with credential "([^"]*)" to "([^"]*)"$`, e.issueCredential)

	s.Step(`^"([^"]*)" has a holder profile with signature type "([^"]*)" and DID key type "([^"]*)"$`,
		e.createBasicHolderProfile)
	s.Step(`^"([^"]*)" sends response to DIDAuth request from "([^"]*)"$`, e.sendDIDAuthResponse)
	s.Step(`^"([^"]*)" stores the "([^"]*)" in wallet$`, e.storeCredentialHolder)

	s.Step(`^"([^"]*)" has a verifier profile$`, e.createBasicVerifierProfile)
	s.Step(`^"([^"]*)" verifies the DIDAuth response from "([^"]*)"$`, e.validateDIDAuthResponse)
	s.Step(`^"([^"]*)" verifies the "([^"]*)" presented by "([^"]*)"$`, e.generateAndVerifyPresentation)
	s.Step(`^Revoke verifiable presentation credential status provided by "([^"]*)"$`, e.revokePresentationCred)
}

//nolint: funlen
func (e *Steps) signAndVerifyPresentation(holder, signatureType, checksList, result, respMessage string) error {
	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	vc, err := verifiable.ParseCredential(e.bddContext.CreatedCredential,
		verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(e.bddContext.VDRI).PublicKeyFetcher()),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	// create verifiable presentation from vc
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
	if err != nil {
		return err
	}

	vpBytes, err := vp.MarshalJSON()
	if err != nil {
		return err
	}

	profileName := "holder-" + uuid.New().String()

	err = e.createHolderProfile(profileName, signatureType)
	if err != nil {
		return err
	}

	domain := "example.com"
	challenge := uuid.New().String()

	vpBytes, err = e.signPresentation(profileName, vpBytes, domain, challenge)
	if err != nil {
		return err
	}

	checks := strings.Split(checksList, ",")

	req := &verifierops.VerifyPresentationRequest{
		Presentation: vpBytes,
		Opts: &verifierops.VerifyPresentationOptions{
			Checks:    checks,
			Domain:    domain,
			Challenge: challenge,
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	verifierProfileID := uuid.New().String()

	err = e.createBasicVerifierProfile(verifierProfileID)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(verifyPresentationURLFormat, verifierProfileID)

	resp, err := bddutil.HTTPDo(http.MethodPost, endpointURL, "", "rw_token",
		bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	return verify(resp, checks, result, respMessage)
}

func (e *Steps) createProfile(profileName, did, privateKey, keyID, holder, didMethod, signatureType,
	keyType string) error {
	template, ok := e.bddContext.TestData["profile_request_template.json"]
	if !ok {
		return fmt.Errorf("unable to find profile request template")
	}

	profileRequest := operation.ProfileRequest{}

	if err := json.Unmarshal(template, &profileRequest); err != nil {
		return err
	}

	profileRequest.Name = profileName
	profileRequest.DID = did
	profileRequest.DIDPrivateKey = privateKey
	profileRequest.SignatureRepresentation = bddutil.GetSignatureRepresentation(holder)
	profileRequest.OverwriteIssuer = true
	profileRequest.SignatureType = signatureType
	profileRequest.DIDKeyType = keyType
	profileRequest.DIDKeyID = keyID

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, issuerURL+"profile", "", //nolint: bodyclose
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

	profileResponse := vcsstorage.IssuerProfile{}

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

func (e *Steps) getProfileData(profileName string) (*vcsstorage.IssuerProfile, error) {
	// False positive on linter bodyclose
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := bddutil.HTTPDo(http.MethodGet, fmt.Sprintf(issuerURL+"profile/%s", profileName), //nolint: bodyclose
		"", "rw_token", nil)
	if err != nil {
		return nil, err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	profileResponse := &vcsstorage.IssuerProfile{}

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

	resp, err := bddutil.HTTPDo(http.MethodPost, endpointURL, "", "rw_token", //nolint: bodyclose
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

	e.bddContext.CreatedCredential = respBytes

	return e.checkVC(respBytes, profileName)
}

func (e *Steps) createProfileAndCredential(user, credential, did, privateKey, keyID, signatureType,
	keyType string) error {
	// reuse existing profile with same did and key
	profileName, ok := e.bddContext.Args[bddutil.GetProfileNameKey(fmt.Sprintf("%s_%s_%s", did, privateKey, keyID))]
	if !ok {
		profileName = fmt.Sprintf("%s_%s", strings.ToLower(user), uuid.New().String())

		err := e.createProfile(profileName, did, privateKey, keyID, "JWS", "", signatureType, keyType)
		if err != nil {
			return fmt.Errorf("failed to create profile: %w", err)
		}

		e.bddContext.Args[bddutil.GetProfileNameKey(fmt.Sprintf("%s_%s_%s", did, privateKey, keyID))] = profileName
	}

	err := e.createCredential(credential, profileName)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	e.bddContext.Args[bddutil.GetCredentialKey(user)] = string(e.bddContext.CreatedCredential)

	return nil
}

func (e *Steps) createProfileAndPresentation(user, credential, did, privateKey, keyID, signatureType,
	keyType string) error {
	// reuse existing profile with same did and key
	profileName, ok := e.bddContext.Args[bddutil.GetProfileNameKey(fmt.Sprintf("%s_%s_%s", did, privateKey, keyID))]
	if !ok {
		profileName = fmt.Sprintf("%s_%s", strings.ToLower(user), uuid.New().String())

		err := e.createProfile(profileName, did, privateKey, keyID, "JWS", "", signatureType, keyType)
		if err != nil {
			return fmt.Errorf("failed to create profile: %w", err)
		}

		e.bddContext.Args[bddutil.GetProfileNameKey(fmt.Sprintf("%s_%s_%s", did, privateKey, keyID))] = profileName
	}

	profileResponse, err := e.getProfileData(profileName)
	if err != nil {
		return err
	}

	err = e.createCredential(credential, profileName)
	if err != nil {
		return err
	}

	signingKey := base58.Decode(privateKey)

	created := time.Now()
	signatureSuite := ed25519signature2018.New(suite.WithSigner(bddutil.GetSigner(signingKey)))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: bddutil.GetSignatureRepresentation("JWS"),
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

func (e *Steps) createProfileAndStoreCredentialFromFile(vcFile, profileName string) error {
	err := e.createProfile(profileName, "", "", "", "", "", "Ed25519Signature2018", "Ed25519")
	if err != nil {
		return err
	}

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

	resp, err := bddutil.HTTPDo(http.MethodPost, issuerURL+"store", "", "rw_token", //nolint: bodyclose
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
	resp, err := bddutil.HTTPDo(http.MethodGet, issuerURL+"retrieve?id="+escapedCredentialID+ //nolint: bodyclose
		"&profile="+escapedProfileName, "", "rw_token", nil)
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
		return fmt.Errorf("failed to validate of retrieved VC : %w", err)
	}

	if !b {
		return fmt.Errorf(" validation of retrieved VC failed")
	}

	return nil
}

func (e *Steps) verifyCredential(checksList, result, respMessage string) error {
	checks := strings.Split(checksList, ",")

	req := &verifierops.CredentialsVerificationRequest{
		Credential: e.bddContext.CreatedCredential,
		Opts: &verifierops.CredentialsVerificationOptions{
			Checks: checks,
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	verifierProfileID := uuid.New().String()

	err = e.createBasicVerifierProfile(verifierProfileID)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(verifyCredentialURLFormat, verifierProfileID)

	resp, err := bddutil.HTTPDo(http.MethodPost, endpointURL, "",
		"rw_token", bytes.NewBuffer(reqBytes))
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

	if result == "successful" { //nolint:nestif
		if resp.StatusCode != http.StatusOK {
			return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
		}

		verifiedResp := verifierops.CredentialsVerificationSuccessResponse{}

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

func (e *Steps) revokePresentationCred(user string) error {
	vpBytes := e.bddContext.Args[user]

	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	vp, err := verifiable.ParsePresentation([]byte(vpBytes), verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	for _, cred := range vp.Credentials() {
		credBytes, err := json.Marshal(cred.(map[string]interface{}))
		if err != nil {
			return err
		}

		vc, err := verifiable.ParseCredential(credBytes, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		if err != nil {
			return err
		}

		if err := e.storeCredential(vc.Issuer.CustomFields["name"].(string), credBytes); err != nil {
			return err
		}

		if err := e.updateCredentialStatus(vc.ID, vc.Issuer.CustomFields["name"].(string)); err != nil {
			return err
		}
	}

	return nil
}

func (e *Steps) revokeCredential() error {
	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	vc, err := verifiable.ParseCredential(e.bddContext.CreatedCredential, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	return e.updateCredentialStatus(vc.ID, vc.Issuer.CustomFields["name"].(string))
}

func (e *Steps) updateCredentialStatus(credID, profileName string) error {
	storeRequest := operation.UpdateCredentialStatusRequest{}

	storeRequest.CredentialID = credID
	storeRequest.CredentialStatus.Type = csl.StatusList2021Entry
	storeRequest.CredentialStatus.Status = "1"

	requestBytes, err := json.Marshal(storeRequest)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(updateCredentialStatusURLFormat, profileName)

	resp, err := bddutil.HTTPDo(http.MethodPost, endpointURL, "", //nolint: bodyclose
		"rw_token", bytes.NewBuffer(requestBytes))
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
	profileResponse *vcsstorage.IssuerProfile) error {
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

func (e *Steps) createHolderProfile(profileName, signatureType string) error {
	profileRequest := holderops.HolderProfileRequest{
		Name:                    profileName,
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           signatureType,
		DIDKeyType:              "Ed25519",
	}

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, holderURL+"/holder/profile", "", //nolint: bodyclose
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

	profileResponse := vcsstorage.HolderProfile{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, profileResponse.DID, 10)
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) signPresentation(profileName string, vp []byte, domain, challenge string) ([]byte, error) {
	req := &holderops.SignPresentationRequest{
		Presentation: vp,
		Opts: &holderops.SignPresentationOptions{
			Challenge: challenge,
			Domain:    domain,
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	endpointURL := fmt.Sprintf(signPresentationURLFormat, profileName)

	resp, err := bddutil.HTTPDo(http.MethodPost, endpointURL, "application/json", //nolint: bodyclose
		"rw_token", bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
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

func (e *Steps) createBasicIssuerProfile(profileName, signatureType, keyType string) error {
	return e.createProfile(profileName, "", "", "", "JWS", "did:orb", signatureType, keyType)
}

func (e *Steps) createBasicHolderProfile(profileName, signatureType, keyType string) error {
	profileRequest := &holderops.HolderProfileRequest{}

	profileRequest.Name = profileName
	profileRequest.SignatureType = signatureType
	profileRequest.DIDKeyType = keyType
	profileRequest.OverwriteHolder = true

	return e.callHolderProfileService(profileRequest)
}

func (e *Steps) callHolderProfileService(profileRequest *holderops.HolderProfileRequest) error {
	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, holderURL+"/holder/profile", "", //nolint: bodyclose
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

	profileResponse := vcsstorage.HolderProfile{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, profileResponse.DID, 10)
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) createAndSendDIDAuthRequest(issuer, holder string) error {
	challenge := uuid.New().String()
	e.bddContext.Args[bddutil.GetProofChallengeKey(issuer)] = challenge

	// replacement for CHAPI call
	e.bddContext.Data[bddutil.GetIssuerHolderCommKey(issuer, holder)] = &bddutil.ProofDataOpts{
		Challenge: challenge,
		Domain:    domain,
	}

	return nil
}

func (e *Steps) sendDIDAuthResponse(holder, issuer string) error {
	data, ok := e.bddContext.Data[bddutil.GetIssuerHolderCommKey(issuer, holder)]
	if !ok {
		return errors.New("no DID Auth request found")
	}

	didAuthReq, ok := data.(*bddutil.ProofDataOpts)
	if !ok {
		return errors.New("invalid did auth request type")
	}

	pres := verifiable.Presentation{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		},
		Type: []string{"VerifiablePresentation"},
	}

	presByte, err := pres.MarshalJSON()
	if err != nil {
		return err
	}

	req := &holderops.SignPresentationRequest{
		Presentation: presByte,
		Opts: &holderops.SignPresentationOptions{
			Challenge: didAuthReq.Challenge,
			Domain:    didAuthReq.Domain,
		},
	}

	signedVPByte, err := e.callSignPresentation(holder, req)
	if err != nil {
		return err
	}

	err = e.validatePresentation(signedVPByte)
	if err != nil {
		return err
	}

	// replacement for CHAPI response for DIDAuth
	e.bddContext.Args[bddutil.GetIssuerHolderCommKey(issuer, holder)] = string(signedVPByte)

	return nil
}

func (e *Steps) callSignPresentation(profileName string, req *holderops.SignPresentationRequest) ([]byte, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	endpointURL := fmt.Sprintf(signPresentationURLFormat, profileName)

	resp, err := bddutil.HTTPDo(http.MethodPost, endpointURL, "application/json", //nolint: bodyclose
		"rw_token", bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func (e *Steps) validatePresentation(signedVCByte []byte) error {
	signedVCResp := make(map[string]interface{})

	err := json.Unmarshal(signedVCByte, &signedVCResp)
	if err != nil {
		return err
	}

	proof, ok := signedVCResp["proof"].(map[string]interface{})
	if !ok {
		return errors.New("unable to convert proof to a map")
	}

	if proof["type"] == "" {
		return errors.New("proof type in empty")
	}

	return nil
}

func (e *Steps) validateDIDAuthResponse(issuer, holder string) error {
	didAuthRespByte := e.bddContext.Args[bddutil.GetIssuerHolderCommKey(issuer, holder)]

	checks := []string{"proof"}

	req := &verifierops.VerifyPresentationRequest{
		Presentation: []byte(didAuthRespByte),
		Opts: &verifierops.VerifyPresentationOptions{
			Checks:    checks,
			Domain:    domain,
			Challenge: e.bddContext.Args[bddutil.GetProofChallengeKey(issuer)],
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(verifyPresentationURLFormat, issuer)

	resp, err := bddutil.HTTPDo(http.MethodPost, endpointURL, "",
		"rw_token", bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	return verify(resp, checks, "successful", "proof")
}

func (e *Steps) issueCredential(issuer, flow, credentialFile, holder string) error {
	return e.createCredential(credentialFile, issuer)
}

func (e *Steps) storeCredentialHolder(holder, flow string) error {
	e.bddContext.Args[bddutil.GetCredentialKey(holder)] = string(e.bddContext.CreatedCredential)

	return nil
}

func (e *Steps) createBasicVerifierProfile(profileID string) error {
	profileRequest := &vcsstorage.VerifierProfile{}

	profileRequest.ID = profileID
	profileRequest.Name = profileID

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, verifierURL+"/verifier/profile", "", //nolint: bodyclose
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

func (e *Steps) generateAndVerifyPresentation(verifierID, flow, holder string) error { //nolint:funlen
	cred := e.bddContext.Args[bddutil.GetCredentialKey(holder)]

	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return fmt.Errorf("create document loader: %w", err)
	}

	vc, err := verifiable.ParseCredential([]byte(cred), verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	pres, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
	if err != nil {
		return err
	}

	pres.Context = append(pres.Context, "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json")

	presByte, err := pres.MarshalJSON()
	if err != nil {
		return err
	}

	challenge := uuid.New().String()
	verifierDomain := "verifier.example.com"

	req := &holderops.SignPresentationRequest{
		Presentation: presByte, Opts: &holderops.SignPresentationOptions{
			Challenge: challenge, Domain: verifierDomain,
		},
	}

	signedVPByte, err := e.callSignPresentation(holder, req)
	if err != nil {
		return err
	}

	checks := []string{"proof"}

	verifyReq := &verifierops.VerifyPresentationRequest{
		Presentation: signedVPByte,
		Opts: &verifierops.VerifyPresentationOptions{
			Checks:    checks,
			Domain:    verifierDomain,
			Challenge: challenge,
		},
	}

	reqBytes, err := json.Marshal(verifyReq)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(verifyPresentationURLFormat, verifierID)

	resp, err := bddutil.HTTPDo(http.MethodPost, endpointURL, "",
		"rw_token", bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	return verify(resp, checks, "successful", "proof")
}
