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
	"strings"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

// nolint: gochecknoglobals
var vcsFormatToOIDC4CI = map[vcsverifiable.Format]vcsverifiable.OIDCFormat{ //nolint
	vcsverifiable.Jwt: vcsverifiable.JwtVCJsonLD,
	vcsverifiable.Ldp: vcsverifiable.LdpVC,
}

func (e *Steps) issueVC(credential, profileVersionedID, organizationName string) error {
	chunks := strings.Split(profileVersionedID, "/")
	profileID, profileVersion := chunks[0], chunks[1]
	if _, err := e.createCredential(credentialServiceURL,
		credential, profileID, profileVersion, organizationName, 0); err != nil {
		return err
	}

	credBytes := e.bddContext.CreatedCredential
	checkProof := true

	if e.bddContext.IssuerProfiles[profileVersionedID].VCConfig.Format == vcsverifiable.Jwt {
		loader, err := bddutil.DocumentLoader()
		if err != nil {
			return fmt.Errorf("create document loader: %w", err)
		}

		cred, err := verifiable.ParseCredential(credBytes, verifiable.WithDisabledProofCheck(),
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

	return e.checkVC(credBytes, profileVersionedID, checkProof)
}

func (e *Steps) createCredential(
	issueCredentialURL,
	credential,
	profileID,
	profileVersion,
	organizationName string,
	didIndex int,
) (string, error) {
	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]

	template, ok := e.bddContext.TestData[credential]
	if !ok {
		return "", fmt.Errorf("unable to find credential '%s' request template", credential)
	}

	loader, err := bddutil.DocumentLoader()
	if err != nil {
		return "", fmt.Errorf("create document loader: %w", err)
	}

	cred, err := verifiable.ParseCredential(template, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return "", err
	}

	cred.ID = uuid.New().URN()

	subjs, ok := cred.Subject.([]verifiable.Subject)
	if !ok {
		return cred.ID, fmt.Errorf("cred subject has wrong type, not verifiable.Subject")
	}

	if len(e.bddContext.CredentialSubject) > didIndex && e.bddContext.CredentialSubject[didIndex] != "" {
		subjs[0].ID = e.bddContext.CredentialSubject[didIndex]
	}

	issuerVCFormat := e.bddContext.IssuerProfiles[fmt.Sprintf("%s/%s", profileID, profileVersion)].VCConfig.Format
	oidcVCFormat := vcsFormatToOIDC4CI[issuerVCFormat]

	reqData, err := vcprovider.GetIssueCredentialRequestData(cred, oidcVCFormat)
	if err != nil {
		return cred.ID, fmt.Errorf("unable to get issue credential request data: %w", err)
	}

	req := &model.IssueCredentialData{
		Credential: reqData,
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return cred.ID, err
	}

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, issueCredentialURL, profileID, profileVersion)

	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", token, //nolint: bodyclose
		bytes.NewBuffer(requestBytes), e.tlsConfig)
	if err != nil {
		return cred.ID, err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return cred.ID, err
	}

	if resp.StatusCode != http.StatusOK {
		return cred.ID, bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	e.Lock()
	e.bddContext.CreatedCredential = respBytes
	e.Unlock()

	return cred.ID, nil
}

func (e *Steps) verifyVC(profileVersionedID, organizationName string) error {
	chunks := strings.Split(profileVersionedID, "/")
	profileID, profileVersion := chunks[0], chunks[1]
	result, err := e.getVerificationResult(credentialServiceURL, profileID, profileVersion, organizationName)
	if err != nil {
		return err
	}

	if result.Checks != nil {
		return fmt.Errorf("credential verification failed: %+v", result.Checks)
	}

	return nil
}

func (e *Steps) verifyRevokedVC(profileVersionedID, organizationName string) error {
	chunks := strings.Split(profileVersionedID, "/")
	profileID, profileVersion := chunks[0], chunks[1]
	result, err := e.getVerificationResult(credentialServiceURL, profileID, profileVersion, organizationName)
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

func (e *Steps) verifyVCInvalidFormat(verifierProfileVersionedID, organizationName string) error {
	chunks := strings.Split(verifierProfileVersionedID, "/")
	profileID, profileVersion := chunks[0], chunks[1]
	result, err := e.getVerificationResult(credentialServiceURL, profileID, profileVersion, organizationName)
	if result != nil {
		return fmt.Errorf("verification result is not nil")
	}

	if err == nil || !strings.Contains(err.Error(), "invalid format, should be") {
		return fmt.Errorf("error expectd, but got nil")
	}

	return nil
}

func (e *Steps) revokeVCWithError(profileVersionedID, organizationName string) error {
	err := e.revokeVC(profileVersionedID, organizationName)
	if err == nil {
		return fmt.Errorf("error expected, but got nil")
	}

	if !strings.Contains(err.Error(), "no documents in result") {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (e *Steps) revokeVC(profileVersionedID, organizationName string) error {
	chunks := strings.Split(profileVersionedID, "/")
	profileID, profileVersion := chunks[0], chunks[1]
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
		ProfileID:      profileID,
		ProfileVersion: profileVersion,
		CredentialID:   cred.ID,
		CredentialStatus: model.CredentialStatus{
			Status: "true",
			Type:   string(e.bddContext.IssuerProfiles[profileVersionedID].VCConfig.Status.Type),
		},
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(updateCredentialStatusURLFormat, credentialServiceURL)

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
	verifyCredentialURL, profileID, profileVersion, organizationName string) (*model.VerifyCredentialResponse, error) {
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

	endpointURL := fmt.Sprintf(verifyCredentialURLFormat, verifyCredentialURL, profileID, profileVersion)
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

func (e *Steps) checkVC(vcBytes []byte, profileVersionedID string, checkProof bool) error {
	vcMap, err := getVCMap(vcBytes)
	if err != nil {
		return err
	}

	expectedStatusType := e.bddContext.IssuerProfiles[profileVersionedID].VCConfig.Status.Type
	err = checkCredentialStatusType(vcMap, string(expectedStatusType))
	if err != nil {
		return err
	}

	err = checkIssuer(vcMap, strings.Split(profileVersionedID, "/")[0])
	if err != nil {
		return err
	}

	if checkProof {
		return e.checkSignatureHolder(vcMap, profileVersionedID)
	}

	return nil
}

func (e *Steps) checkSignatureHolder(vcMap map[string]interface{},
	profileVersionedID string) error {
	proof, found := vcMap["proof"]
	if !found {
		return fmt.Errorf("unable to find proof in VC map")
	}

	proofMap, ok := proof.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unable to assert proof field type as map[string]interface{}")
	}

	profileSigRepresentation := e.bddContext.IssuerProfiles[profileVersionedID].VCConfig.SignatureRepresentation

	switch profileSigRepresentation {
	case verifiable.SignatureJWS:
		_, found = proofMap["jws"]
		if !found {
			return fmt.Errorf("unable to find jws in proof")
		}
	case verifiable.SignatureProofValue:
		_, found = proofMap["proofValue"]
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
		return bddutil.ExpectedStringError(expected, credentialStatusType)
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
