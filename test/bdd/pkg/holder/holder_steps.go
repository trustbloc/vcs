/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package holder

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
	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	"github.com/trustbloc/edge-service/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	holderURL = "http://localhost:8067"

	signPresentationURLFormat = holderURL + "/%s" + "/prove/presentations"
)

const (
	validVPWithoutProof = `{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"
		],
		"type": "VerifiablePresentation",
		"verifiableCredential": {
		   "@context":[
			  "https://www.w3.org/2018/credentials/v1",
			  "https://w3id.org/citizenship/v1"
		   ],
		   "credentialSubject":{
			  "birthCountry":"Bahamas",
			  "birthDate":"1958-08-17",
			  "commuterClassification":"C1",
			  "familyName":"SMITH",
			  "gender":"Male",
			  "givenName":"JOHN",
			  "id":"did:key:z6Mkte9e5E2GRozAgYyhktX7eTt9woCR4yJLnaqC88FQCSyY",
			  "image":"data:image/png;base64,iVBORw0KGgo...kJggg==",
			  "lprCategory":"C09",
			  "lprNumber":"000-000-204",
			  "residentSince":"2015-01-01",
			  "type":[
				 "PermanentResident",
				 "Person"
			  ]
		   },
		   "description":"Government of Example Permanent Resident Card.",
		   "identifier":"83627465",
		   "issuanceDate":"2020-04-22T10:37:22Z",
		   "issuer":"did:trustbloc:xyolrdw2d32e3d128120asjnkjas-1221-=1",
		   "name":"Permanent Resident Card",
		   "proof":{
			  "created":"2020-04-27T18:48:27Z",
			  "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..` +
		`H7d6YSx3KnqXwzVRNbD4Jn_S2l-iThsTkc-SPQvnsjXmpaHCf4EO5j7gMCYN0nKPfHk2ny_ikH4xqIjIyVwaBA",
			  "proofPurpose":"assertionMethod",
			  "type":"Ed25519Signature2018",
			  "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiDfx1g3LUn8QeQlD4ny84XjsUSqx_9UC6cyPj` +
		`963CIetw#bG9jYWwtbG9jazovL2N1c3RvbS9tYXN0ZXIva2V5L0JBV2otbFdaUVJhQ2hJckZGMlhTaDJSRVJoVWtZOEt5Z0xualZYTllYZjg9"
		   },
		   "type":[
			  "VerifiableCredential",
			  "PermanentResidentCard"
		   ]
		}
	}`
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
	s.Step(`^Holder Profile "([^"]*)" is created with DID "([^"]*)", privateKey "([^"]*)", signatureHolder "([^"]*)", uniRegistrar '([^']*)', didMethod "([^"]*)", signatureType "([^"]*)" and keyType "([^"]*)"$`, // nolint
		e.createHolderProfile)
	s.Step(`^Holder profile "([^"]*)" can be retrieved with DID "([^"]*)" and signatureType "([^"]*)"$`,
		e.getProfile)
	s.Step(`^Holder "([^"]*)" generates presentation for the VC received from the Government$`,
		e.signAndValidatePresentation)
}

// nolint: funlen
func (e *Steps) createHolderProfile(profileName, did, privateKey, signatureRep, uniRegistrar,
	didMethod, signatureType, keyType string) error {
	profileRequest := operation.HolderProfileRequest{}

	var u operation.UNIRegistrar

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

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := http.Post(holderURL+"/holder/profile", "", bytes.NewBuffer(requestBytes)) //nolint: bodyclose

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

	profileResponse := profile.HolderProfile{}

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

func (e *Steps) getProfile(profileName, did, signatureType string) error {
	profileResponse, err := e.getProfileData(profileName)
	if err != nil {
		return err
	}

	return e.checkProfileResponse(profileName, did, signatureType, profileResponse)
}

func (e *Steps) getProfileData(profileName string) (*profile.HolderProfile, error) {
	resp, err := http.Get(fmt.Sprintf(holderURL+"/holder/profile/%s", profileName)) //nolint: bodyclose
	if err != nil {
		return nil, err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	profileResponse := &profile.HolderProfile{}

	err = json.Unmarshal(respBytes, profileResponse)
	if err != nil {
		return nil, err
	}

	return profileResponse, nil
}

func (e *Steps) signAndValidatePresentation(profileName string) error {
	signedVPByte, err := e.signPresentation(profileName)
	if err != nil {
		return err
	}

	return e.validatePresentation(signedVPByte)
}

func (e *Steps) signPresentation(profileName string) ([]byte, error) {
	req := &operation.SignPresentationRequest{
		Presentation: []byte(validVPWithoutProof),
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	endpointURL := fmt.Sprintf(signPresentationURLFormat, profileName)

	resp, err := http.Post(endpointURL, "application/json", bytes.NewBuffer(reqBytes)) //nolint
	if err != nil {
		return nil, err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %s", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func (e *Steps) validatePresentation(signedVPByte []byte) error {
	signedVPResp := make(map[string]interface{})

	err := json.Unmarshal(signedVPByte, &signedVPResp)
	if err != nil {
		return err
	}

	proof, ok := signedVPResp["proof"].(map[string]interface{})
	if !ok {
		return errors.New("unable to convert proof to a map")
	}

	if proof["type"] == "" {
		return errors.New("proof type in empty")
	}

	proofPurpose, ok := proof["proofPurpose"]
	if !ok {
		return fmt.Errorf("proof purpose not found")
	}

	proofPurposeStr, ok := proofPurpose.(string)
	if !ok {
		return fmt.Errorf("proof purpose not a string")
	}

	expected := "authentication"
	if proofPurposeStr != expected {
		return bddutil.ExpectedStringError(expected, proofPurposeStr)
	}

	return nil
}

func (e *Steps) checkProfileResponse(expectedProfileResponseName, expectedProfileDID, expectedSignatureType string,
	profileResponse *profile.HolderProfile) error {
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
