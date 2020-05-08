/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	log "github.com/sirupsen/logrus"
	didclient "github.com/trustbloc/trustbloc-did-method/pkg/did"

	"github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
	"github.com/trustbloc/edge-service/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	issuerURL = "http://localhost:8070"

	issueCredentialURLFormat           = issuerURL + "/%s" + "/credentials/issueCredential"
	composeAndIssueCredentialURLFormat = issuerURL + "/%s" + "/credentials/composeAndIssueCredential"
)

const (
	composeCredReqFormat = `{
	   "issuer":"did:example:uoweu180928901",
	   "subject":"did:example:oleh394sqwnlk223823ln",
	   "types":[
		  "UniversityDegree"
	   ],
	   "issuanceDate":"2020-03-25T19:38:54.45546Z",
	   "expirationDate":"2020-06-25T19:38:54.45546Z",
	   "claims":{
		  "customField":"customFieldVal",
		  "name":"John Doe"
	   },
	   "evidence":{
		  "customField":"customFieldVal",
		  "id":"http://example.com/policies/credential/4",
		  "type":"IssuerPolicy"
	   },
	   "termsOfUse":{
		  "id":"http://example.com/policies/credential/4",
		  "type":"IssuerPolicy"
	   },
	   "proofFormat":"jws",
	   "proofFormatOptions":{
		  "kid":` + `"%s"` + `,
          "proofPurpose":` + `"%s"` + `
	   }
	}`

	domain          = "example.com"
	assertionMethod = "assertionMethod"
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
	s.Step(`^"([^"]*)" has her "([^"]*)" issued as "([^"]*)"$`, e.prepareCredential)
	s.Step(`^"([^"]*)" has her "([^"]*)" issued as "([^"]*)" and presentable as "([^"]*)"$`, e.getPresentation)
	s.Step(`^"([^"]*)" has a DID with the public key generated from Issuer Service - Generate Keypair API$`, e.createDID)
	s.Step(`^"([^"]*)" creates an Issuer Service profile "([^"]*)" with the DID$`, e.createIssuerProfile)
	s.Step(`^"([^"]*)" application service verifies the credential created by Issuer Service - Issue Credential API with it's DID$`, //nolint: lll
		e.issueAndVerifyCredential)
	s.Step(`^"([^"]*)" application service verifies the credential created by Issuer Service - Compose And Issue Credential API with it's DID$`, //nolint: lll
		e.composeIssueAndVerifyCredential)
}

func (e *Steps) createDID(user string) error {
	doc, err := e.createSidetreeDID()
	if err != nil {
		return err
	}

	e.bddContext.Data[bddutil.GetDIDDocKey(user)] = doc

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, doc.ID, 10)

	return err
}

func (e *Steps) generateKeypair() (string, string, error) {
	resp, err := http.Get(issuerURL + "/kms/generatekeypair") //nolint: bodyclose
	if err != nil {
		return "", "", err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	generateKeyPairResponse := operation.GenerateKeyPairResponse{}

	err = json.Unmarshal(respBytes, &generateKeyPairResponse)
	if err != nil {
		return "", "", err
	}

	return generateKeyPairResponse.PublicKey, generateKeyPairResponse.KeyID, nil
}

func (e *Steps) createIssuerProfile(user, profileName string) error {
	template, ok := e.bddContext.TestData["profile_request_template.json"]
	if !ok {
		return fmt.Errorf("unable to find profile request template")
	}

	profileRequest := operation.ProfileRequest{}

	err := json.Unmarshal(template, &profileRequest)
	if err != nil {
		return err
	}

	did, err := e.getDIDforUser(user)
	if err != nil {
		return err
	}

	profileRequest.Name = uuid.New().String() + profileName
	profileRequest.DID = did.ID
	profileRequest.SignatureType = "JsonWebSignature2020"

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := http.Post(issuerURL+"/profile", "", bytes.NewBuffer(requestBytes)) //nolint: bodyclose
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

	if did.ID != profileResponse.DID {
		return fmt.Errorf("DID not saved in the profile - expected=%s actual=%s", did.ID, profileResponse.DID)
	}

	e.bddContext.Args[bddutil.GetProfileNameKey(user)] = profileResponse.Name

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, profileResponse.DID, 10)

	return err
}

func (e *Steps) createSidetreeDID() (*docdid.Doc, error) {
	base58PubKey, keyID, err := e.generateKeypair()
	if err != nil {
		return nil, err
	}

	c := didclient.New(didclient.WithTLSConfig(e.bddContext.TLSConfig))

	_, ed25519PubKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return c.CreateDID("testnet.trustbloc.local",
		didclient.WithPublicKey(&didclient.PublicKey{ID: keyID, Type: didclient.JWSVerificationKey2020,
			Value: base58.Decode(base58PubKey), KeyType: didclient.Ed25519KeyType,
			Usage: []string{didclient.KeyUsageOps, didclient.KeyUsageGeneral, didclient.KeyUsageAssertion,
				didclient.KeyUsageAuth},
			Encoding: didclient.PublicKeyEncodingJwk}),
		didclient.WithPublicKey(&didclient.PublicKey{ID: "recovery",
			Encoding: didclient.PublicKeyEncodingJwk, Value: ed25519PubKey,
			KeyType: didclient.Ed25519KeyType, Recovery: true}))
}

func (e *Steps) verifyCredential(signedVCByte []byte, domain, challenge, purpose string) error { // nolint: gocyclo
	signedVCResp := make(map[string]interface{})

	err := json.Unmarshal(signedVCByte, &signedVCResp)
	if err != nil {
		return err
	}

	proof, ok := signedVCResp["proof"].(map[string]interface{})
	if !ok {
		return errors.New("unable to convert proof to a map")
	}

	if proof["type"] != "JsonWebSignature2020" {
		return errors.New("proof type is not valid")
	}

	if proof["jws"] == "" {
		return errors.New("proof jws value is empty")
	}

	if challenge != "" && challenge != proof["challenge"].(string) {
		return fmt.Errorf("proof challenge doesn't match ; expected=%s actual=%s", challenge,
			proof["challenge"].(string))
	}

	if domain != "" && domain != proof["domain"].(string) {
		return fmt.Errorf("proof domain doesn't match ; expected=%s actual=%s", domain,
			proof["domain"].(string))
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

	return nil
}

func (e *Steps) issueCredential(user, did, cred, domain, challenge, keyID string) ([]byte, error) {
	if _, err := bddutil.ResolveDID(e.bddContext.VDRI, did, 10); err != nil {
		return nil, err
	}

	req := &operation.IssueCredentialRequest{
		Credential: e.bddContext.TestData[cred],
		Opts: &operation.IssueCredentialOptions{
			AssertionMethod: keyID,
			Challenge:       challenge,
			Domain:          domain,
		},
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, e.bddContext.Args[bddutil.GetProfileNameKey(user)])

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

func (e *Steps) issueAndVerifyCredential(user string) error {
	var did *docdid.Doc

	var err error

	if did, err = e.getDIDforUser(user); err != nil {
		return err
	}

	vms := did.VerificationMethods(docdid.AssertionMethod)[docdid.AssertionMethod]
	if len(vms) == 0 {
		return fmt.Errorf("no authentication method in DID created")
	}

	log.Infof("DID for signing %s", did.ID)

	challenge := uuid.New().String()

	signedVCByte, err := e.issueCredential(user, did.ID, "university_certificate.json", domain, challenge,
		vms[0].PublicKey.ID)
	if err != nil {
		return err
	}

	return e.verifyCredential(signedVCByte, domain, challenge, assertionMethod)
}

func (e *Steps) composeIssueAndVerifyCredential(user string) error {
	var did *docdid.Doc

	var err error

	if did, err = e.getDIDforUser(user); err != nil {
		return err
	}

	vms := did.VerificationMethods(docdid.AssertionMethod)[docdid.AssertionMethod]
	if len(vms) == 0 {
		return fmt.Errorf("no authentication method in DID created")
	}

	req := fmt.Sprintf(composeCredReqFormat, vms[0].PublicKey.ID, assertionMethod)

	endpointURL := fmt.Sprintf(composeAndIssueCredentialURLFormat, e.bddContext.Args[bddutil.GetProfileNameKey(user)])

	resp, err := http.Post(endpointURL, "application/json", bytes.NewBufferString(req)) //nolint
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response : %s", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return e.verifyCredential(responseBytes, "", "", assertionMethod)
}

func (e *Steps) createCredential(user, cred string) ([]byte, error) {
	did, err := e.getDIDforUser(user)
	if err != nil {
		return nil, err
	}

	vms := did.VerificationMethods(docdid.AssertionMethod)[docdid.AssertionMethod]
	if len(vms) == 0 {
		return nil, fmt.Errorf("no authentication method in DID created")
	}

	if er := e.createIssuerProfile(user, uuid.New().String()); er != nil {
		return nil, er
	}

	challenge := uuid.New().String()

	signedVCByte, err := e.issueCredential(user, did.ID, cred, domain, challenge, vms[0].PublicKey.ID)
	if err != nil {
		return nil, err
	}

	if err := e.verifyCredential(signedVCByte, domain, challenge, assertionMethod); err != nil {
		return nil, err
	}

	e.bddContext.Args[bddutil.GetProofChallengeKey(user)] = challenge
	e.bddContext.Args[bddutil.GetProofDomainKey(user)] = domain

	return signedVCByte, nil
}

func (e *Steps) prepareCredential(user, cred, vcred string) error {
	var credEmpty, vcredEmpty = cred == "", vcred == ""

	switch {
	case !vcredEmpty:
		// verifiable credential found in example data.
		vcBytes, ok := e.bddContext.TestData[vcred]
		if !ok {
			return fmt.Errorf("unable to find verifiable credential '%s'", vcred)
		}

		e.bddContext.Args[user] = string(vcBytes)
	case !credEmpty:
		// credential found in example data, create verifiable credential.
		vcBytes, err := e.createCredential(user, cred)
		if err != nil {
			return err
		}

		e.bddContext.Args[bddutil.GetCredentialKey(user)] = string(vcBytes)
	default:
		return fmt.Errorf("invalid args, 'user' and 'credential' are mandatory")
	}

	return nil
}

//nolint: gocyclo,funlen
func (e *Steps) getPresentation(user, cred, vcred, vpres string) error {
	var userEmpty, credEmpty, vcredEmpty, vpresEmpty = user == "", cred == "", vcred == "", vpres == ""

	switch {
	case userEmpty || credEmpty:
		return fmt.Errorf("'user' and 'credential' are mandatory in example data")
	case !vpresEmpty:
		// verifiable presentation is provided in test example data.
		vpBytes, ok := e.bddContext.TestData[vpres]
		if !ok {
			return fmt.Errorf("unable to find verifiable presentation '%s'", vpres)
		}

		vp, err := verifiable.NewPresentation(vpBytes, verifiable.WithDisabledPresentationProofCheck())
		if err != nil {
			return err
		}

		e.bddContext.Args[user] = string(vpBytes)
		e.bddContext.Args[bddutil.GetProofChallengeKey(user)] = ""
		e.bddContext.Args[bddutil.GetProofDomainKey(user)] = ""

		//nolint: errcheck
		if len(vp.Proofs) > 0 {
			if c, ok := vp.Proofs[0]["challenge"]; ok {
				e.bddContext.Args[bddutil.GetProofChallengeKey(user)] = c.(string)
			}

			if d, ok := vp.Proofs[0]["domain"]; ok {
				e.bddContext.Args[bddutil.GetProofDomainKey(user)] = d.(string)
			}
		}

	case !vcredEmpty:
		// create verifiable presentation using verifiable credential from example data.
		vcBytes, ok := e.bddContext.TestData[vcred]
		if !ok {
			return fmt.Errorf("unable to find verifiable presentation '%s'", vpres)
		}

		challenge := uuid.New().String()

		doc, err := e.getDIDforUser(user)
		if err != nil {
			return err
		}

		vpBytes, err := bddutil.CreatePresentation(vcBytes, "JsonWebSignature2020", domain, challenge,
			verifiable.SignatureJWS, e.bddContext.VDRI, doc)
		if err != nil {
			return err
		}

		e.bddContext.Args[user] = string(vpBytes)
		e.bddContext.Args[bddutil.GetProofChallengeKey(user)] = challenge
		e.bddContext.Args[bddutil.GetProofDomainKey(user)] = domain
	default:
		// create verifiable credential and then verifiable presentation from example data credential.
		vcBytes, err := e.createCredential(user, cred)
		if err != nil {
			return err
		}

		challenge := uuid.New().String()

		doc, err := e.getDIDforUser(user)
		if err != nil {
			return err
		}

		vpBytes, err := bddutil.CreatePresentation(vcBytes, "JsonWebSignature2020", domain, challenge,
			verifiable.SignatureJWS, e.bddContext.VDRI, doc)
		if err != nil {
			return err
		}

		e.bddContext.Args[user] = string(vpBytes)
		e.bddContext.Args[bddutil.GetProofChallengeKey(user)] = challenge
		e.bddContext.Args[bddutil.GetProofDomainKey(user)] = domain
	}

	return nil
}

func (e *Steps) getDIDforUser(user string) (*docdid.Doc, error) {
	if doc, ok := e.bddContext.Data[bddutil.GetDIDDocKey(user)]; ok {
		return doc.(*docdid.Doc), nil
	}

	if err := e.createDID(user); err != nil {
		return nil, err
	}

	return e.getDIDforUser(user)
}
