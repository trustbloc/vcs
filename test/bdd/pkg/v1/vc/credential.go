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
	"net/http"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

func (e *Steps) issueVC(credential, vcFormat, profileName, organizationName, signatureRepresentation string) error {
	if err := e.createCredential(credentialServiceURL, credential, vcFormat, profileName, organizationName); err != nil {
		return err
	}

	credBytes := e.bddContext.CreatedCredential
	checkProof := true

	if vcFormat == "jwt_vc" {
		loader, err := bddutil.DocumentLoader()
		if err != nil {
			return fmt.Errorf("create document loader: %w", err)
		}

		cred, err := verifiable.ParseCredential(e.bddContext.CreatedCredential, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		if err != nil {
			return err
		}

		cred.JWT = ""

		credBytes, err = cred.MarshalJSON()
		if err != nil {
			return fmt.Errorf("cred marshal error: %w", err)
		}

		checkProof = false
	}

	return e.checkVC(credBytes, profileName, signatureRepresentation, checkProof)
}

func (e *Steps) createCredential(issueCredentialURL, credential, vcFormat, profileName, organizationName string) error {
	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]

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

	cred.ID = uuid.New().URN()

	reqData, err := getIssueCredentialRequestData(cred, vcFormat)
	if err != nil {
		return fmt.Errorf("unable to get issue credential request data: %w", err)
	}

	req := &model.IssueCredentialData{
		Credential: reqData,
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, issueCredentialURL, profileName)

	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", token, //nolint: bodyclose
		bytes.NewBuffer(requestBytes), e.tlsConfig)
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	e.Lock()
	e.bddContext.CreatedCredential = respBytes
	e.Unlock()

	return nil
}

func getIssueCredentialRequestData(vc *verifiable.Credential, desiredFormat string) (interface{}, error) {
	switch desiredFormat {
	case string(common.JwtVc):
		claims, err := vc.JWTClaims(false)
		if err != nil {
			return nil, err
		}

		return claims.MarshalUnsecuredJWT()
	case string(common.LdpVc):
		return vc, nil

	default:
		return nil, fmt.Errorf("unsupported format %s", desiredFormat)
	}
}

func (e *Steps) verifyVC(profileName, organizationName string) error {
	result, err := e.getVerificationResult(credentialServiceURL, profileName, organizationName)
	if err != nil {
		return err
	}

	if result.Checks != nil {
		return fmt.Errorf("credential verification failed")
	}

	return nil
}

func (e *Steps) verifyRevokedVC(profileName, organizationName string) error {
	result, err := e.getVerificationResult(credentialServiceURL, profileName, organizationName)
	if err != nil {
		return err
	}

	checks := *result.Checks

	expectedCheck := model.VerifyCredentialCheckResult{
		Check:              "credentialStatus",
		Error:              "revoked",
		VerificationMethod: "",
	}

	if checks[0] != expectedCheck {
		return fmt.Errorf("vc is not revoked. Cheks: %+v", checks)
	}

	return nil
}

func (e *Steps) revokeVC(profileName, organizationName string) error {
	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return err
	}

	e.RLock()
	createdCredential := e.bddContext.CreatedCredential
	e.RUnlock()

	cred, err := verifiable.ParseCredential(createdCredential, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	req := &model.UpdateCredentialStatusRequest{
		CredentialID: cred.ID,
		CredentialStatus: model.CredentialStatus{
			Status: "true",
			Type:   "StatusList2021Entry",
		},
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(updateCredentialStatusURLFormat, credentialServiceURL, profileName)

	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]
	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", token, //nolint: bodyclose
		bytes.NewBuffer(requestBytes), e.tlsConfig)
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	return nil
}

func (e *Steps) getVerificationResult(
	verifyCredentialURL, profileName, organizationName string) (*model.VerifyCredentialResponse, error) {
	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return nil, err
	}

	e.RLock()
	createdCredential := e.bddContext.CreatedCredential
	e.RUnlock()

	cred, err := verifiable.ParseCredential(createdCredential, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return nil, err
	}

	req := &model.VerifyCredentialData{
		Credential: cred,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	endpointURL := fmt.Sprintf(verifyCredentialURLFormat, verifyCredentialURL, profileName)
	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]
	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", token, //nolint: bodyclose
		bytes.NewBuffer(reqBytes), e.tlsConfig)
	if err != nil {
		return nil, err
	}
	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	payload := &model.VerifyCredentialResponse{}

	err = json.Unmarshal(respBytes, &payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func (e *Steps) checkVC(vcBytes []byte, profileName, signatureRepresentation string, checkProof bool) error {
	vcMap, err := getVCMap(vcBytes)
	if err != nil {
		return err
	}

	err = checkCredentialStatusType(vcMap, credentialstatus.StatusList2021Entry)
	if err != nil {
		return err
	}

	err = checkIssuer(vcMap, profileName)
	if err != nil {
		return err
	}

	if checkProof {
		return e.checkSignatureHolder(vcMap, signatureRepresentation)
	}

	return nil
}

func (e *Steps) checkSignatureHolder(vcMap map[string]interface{},
	signatureRepresentation string) error {
	proof, found := vcMap["proof"]
	if !found {
		return fmt.Errorf("unable to find proof in VC map")
	}

	proofMap, ok := proof.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unable to assert proof field type as map[string]interface{}")
	}

	switch signatureRepresentation {
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
		return bddutil.ExpectedStringError(credentialstatus.StatusList2021Entry, credentialStatusType)
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
