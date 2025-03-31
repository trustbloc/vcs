/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/trustbloc/vc-go/status"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/samber/lo"

	"github.com/trustbloc/vc-go/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

// nolint: gochecknoglobals
var vcsFormatToOIDC4CI = map[vcsverifiable.Format]vcsverifiable.OIDCFormat{ //nolint
	vcsverifiable.Jwt: vcsverifiable.JwtVCJsonLD,
	vcsverifiable.Ldp: vcsverifiable.LdpVC,
}

func (e *Steps) issueVC(credential, profileVersionedID string) error {
	chunks := strings.Split(profileVersionedID, "/")
	profileID, profileVersion := chunks[0], chunks[1]
	if _, err := e.createCredential(credentialServiceURL,
		credential, profileID, profileVersion, 0); err != nil {
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

		credBytes, err = cred.MarshalAsJSONLD()
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
	profileVersion string,
	didIndex int,
) (string, error) {
	token := e.bddContext.Args[getOrgAuthTokenKey(fmt.Sprintf("%s/%s", profileID, profileVersion))]

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

	subjs := cred.Contents().Subject

	if len(e.bddContext.CredentialSubject) > didIndex && e.bddContext.CredentialSubject[didIndex] != "" {
		subjs[0].ID = e.bddContext.CredentialSubject[didIndex]
	}

	cred = cred.WithModifiedID(uuid.New().URN()).WithModifiedSubject(subjs)

	issuerVCFormat := e.bddContext.IssuerProfiles[fmt.Sprintf("%s/%s", profileID, profileVersion)].VCConfig.Format
	oidcVCFormat := vcsFormatToOIDC4CI[issuerVCFormat]

	reqData, err := getIssueCredentialRequestData(cred, oidcVCFormat)
	if err != nil {
		return cred.Contents().ID, fmt.Errorf("unable to get issue credential request data: %w", err)
	}

	req := &model.IssueCredentialData{
		Credential: reqData,
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return cred.Contents().ID, err
	}

	endpointURL := fmt.Sprintf(issueCredentialURLFormat, issueCredentialURL, profileID, profileVersion)

	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", token, //nolint: bodyclose
		bytes.NewBuffer(requestBytes), e.tlsConfig)
	if err != nil {
		return cred.Contents().ID, err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return cred.Contents().ID, err
	}

	if resp.StatusCode != http.StatusCreated {
		return cred.Contents().ID, bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	e.Lock()
	e.bddContext.CreatedCredential = respBytes
	e.Unlock()

	return cred.Contents().ID, nil
}

func getIssueCredentialRequestData(vc *verifiable.Credential, desiredFormat vcsverifiable.OIDCFormat) (interface{}, error) {
	switch desiredFormat {
	case vcsverifiable.JwtVCJsonLD, vcsverifiable.JwtVCJson:
		claims, err := vc.JWTClaims(false)
		if err != nil {
			return nil, err
		}

		return claims.MarshalUnsecuredJWT()
	case vcsverifiable.LdpVC, vcsverifiable.CwtVcLD:
		return vc, nil

	default:
		return nil, fmt.Errorf("unsupported format %s", desiredFormat)
	}
}

func (e *Steps) verifyVC(profileVersionedID string) error {
	chunks := strings.Split(profileVersionedID, "/")
	profileID, profileVersion := chunks[0], chunks[1]
	respBytes, err := e.getVerificationResult(credentialServiceURL, profileID, profileVersion, []int{
		http.StatusOK,
	})
	if err != nil {
		return err
	}

	result := &model.VerifyCredentialResponse{}

	err = json.Unmarshal(respBytes, &result)
	if err != nil {
		return err
	}

	if result.Checks != nil {
		return fmt.Errorf("credential verification failed: %+v", result.Checks)
	}

	return nil
}

func (e *Steps) verifyVCRevoked(profileVersionedID string) error {
	return e.verifyVCStatus(profileVersionedID, "revoked")
}

func (e *Steps) verifyVCSuspended(profileVersionedID string) error {
	return e.verifyVCStatus(profileVersionedID, "suspended")
}

func (e *Steps) verifyVCStatus(profileVersionedID, expectedStatus string) error {
	chunks := strings.Split(profileVersionedID, "/")
	profileID, profileVersion := chunks[0], chunks[1]
	respBytes, err := e.getVerificationResult(credentialServiceURL, profileID, profileVersion, []int{
		http.StatusBadRequest,
	})
	if err != nil {
		return err
	}

	result := &model.VerifyCredentialResponse{}

	err = json.Unmarshal(respBytes, &result)
	if err != nil {
		return err
	}

	checks := *result.Checks

	expectedCheck := model.VerifyCredentialCheckResult{
		Check:              "credentialStatus",
		Error:              expectedStatus,
		VerificationMethod: "",
	}

	if checks[0] != expectedCheck {
		return fmt.Errorf("vc is not %s. Checks: %+v", expectedStatus, checks)
	}

	return nil
}

func (e *Steps) verifyVCWithExpectedError(verifierProfileVersionedID, errorMsg string) error {
	chunks := strings.Split(verifierProfileVersionedID, "/")
	profileID, profileVersion := chunks[0], chunks[1]
	bytesResp, err := e.getVerificationResult(credentialServiceURL, profileID, profileVersion, []int{
		http.StatusBadRequest,
	})

	if !strings.Contains(string(bytesResp), errorMsg) {
		return fmt.Errorf("unexpected error %s should contain %s", err.Error(), errorMsg)
	}

	return nil
}

func (e *Steps) revokeVC(profileVersionedID string) error {
	return e.updateVCStatus(profileVersionedID, status.StatusPurposeRevocation, "true")
}

func (e *Steps) revokeVCWithError(profileVersionedID, errorContains string) error {
	err := e.revokeVC(profileVersionedID)
	if err == nil {
		return fmt.Errorf("error expected, but got nil")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (e *Steps) activateVC(profileVersionedID string) error {
	return e.updateVCStatus(profileVersionedID, status.StatusPurposeRevocation, "false")
}

func (e *Steps) activateVCWithError(profileVersionedID, errorContains string) error {
	err := e.activateVC(profileVersionedID)
	if err == nil {
		return fmt.Errorf("error expected, but got nil")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (e *Steps) suspendVC(profileVersionedID string) error {
	return e.updateVCStatus(profileVersionedID, status.StatusPurposeSuspension, "true")
}

func (e *Steps) suspendVCWithError(profileVersionedID, errorContains string) error {
	err := e.suspendVC(profileVersionedID)
	if err == nil {
		return fmt.Errorf("error expected, but got nil")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (e *Steps) unsuspendVC(profileVersionedID string) error {
	return e.updateVCStatus(profileVersionedID, status.StatusPurposeSuspension, "false")
}

func (e *Steps) unsuspendVCWithError(profileVersionedID, errorContains string) error {
	err := e.unsuspendVC(profileVersionedID)
	if err == nil {
		return fmt.Errorf("error expected, but got nil")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (e *Steps) updateVCStatus(profileVersionedID, statusPurpose, desiredStatus string) error {
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
		CredentialID:   cred.Contents().ID,
		CredentialStatus: model.CredentialStatus{
			Status:  desiredStatus,
			Purpose: statusPurpose,
			Type:    string(e.bddContext.IssuerProfiles[profileVersionedID].VCConfig.Status.Type),
		},
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf(updateCredentialStatusURLFormat, credentialServiceURL)

	token := e.bddContext.Args[getOrgAuthTokenKey(chunks[0]+"/"+chunks[1])]
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
	verifyCredentialURL,
	profileID,
	profileVersion string,
	expectedCodes []int,
) ([]byte, error) {
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
		VerifiableCredential: cred,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	endpointURL := fmt.Sprintf(verifyCredentialURLFormat, verifyCredentialURL, profileID, profileVersion)
	token := e.bddContext.Args[getOrgAuthTokenKey(profileID+"/"+profileVersion)]
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

	if !lo.Contains(expectedCodes, resp.StatusCode) {
		return nil, bddutil.ExpectedStatusCodeError(expectedCodes[0], resp.StatusCode, respBytes)
	}

	return respBytes, nil
}

func (e *Steps) checkVC(vcBytes []byte, profileVersionedID string, checkProof bool) error {
	vcMap, err := getVCMap(vcBytes)
	if err != nil {
		return err
	}

	vcStatusConf := e.bddContext.IssuerProfiles[profileVersionedID].VCConfig.Status
	if !vcStatusConf.Disable {
		expectedStatusType := vcStatusConf.Type
		err = checkCredentialStatusTypeAndPurposes(vcMap, string(expectedStatusType), vcStatusConf.Purpose)
		if err != nil {
			return err
		}
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

func checkCredentialStatusTypeAndPurposes(vcMap map[string]interface{}, expectedType string, expectedPurposes []string) error {
	credentialStatusType, purposes, err := getCredentialStatusTypeAndPurpose(vcMap)
	if err != nil {
		return err
	}

	if credentialStatusType != expectedType {
		return bddutil.ExpectedStringError(expectedType, credentialStatusType)
	}

	if len(expectedPurposes) == 0 {
		expectedPurposes = []string{statustype.DefaultStatusPurpose}
	}

	if len(expectedPurposes) != len(purposes) {
		return bddutil.ExpectedStringError(fmt.Sprintf("%v", expectedPurposes), fmt.Sprintf("%v", purposes))
	}

	for _, expectedPurpose := range expectedPurposes {
		if !lo.Contains(purposes, expectedPurpose) {
			return fmt.Errorf("unable to find purpose %s in VC map", expectedPurpose)
		}
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

func getCredentialStatusTypeAndPurpose(vcMap map[string]interface{}) (string, []string, error) {
	credentialStatus, found := vcMap["credentialStatus"]
	if !found {
		return "nil", nil, fmt.Errorf("unable to find credentialStatus in VC map")
	}

	credentialStatusMap, ok := credentialStatus.(map[string]interface{})
	if ok {
		credentialStatusType, purpose, err := getStatusTypeAndPurpose(credentialStatusMap)
		if err != nil {
			return "", nil, err
		}

		return credentialStatusType, []string{purpose}, nil
	}

	credentialStatusArr, ok := credentialStatus.([]interface{})
	if !ok {
		return "", nil, fmt.Errorf("unable to assert credentialStatus field type as map[string]interface{} or []interface{}")
	}

	var purposes []string
	var statusType string

	for _, status := range credentialStatusArr {
		credentialStatusMap, ok = status.(map[string]interface{})
		if !ok {
			return "", nil, fmt.Errorf("unable to assert credentialStatus array element type as map[string]interface{}")
		}

		st, purpose, err := getStatusTypeAndPurpose(credentialStatusMap)
		if err != nil {
			return "", nil, err
		}

		if statusType == "" {
			statusType = st
		} else if statusType != st {
			return "", nil, fmt.Errorf("status type is not consistent")
		}

		purposes = append(purposes, purpose)
	}

	return statusType, purposes, nil
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

func getStatusTypeAndPurpose(credentialStatusMap map[string]interface{}) (string, string, error) {
	statusType, found := credentialStatusMap["type"].(string)
	if !found {
		return "", "", fmt.Errorf("unable to find credentialStatus type in VC map")
	}

	switch vc.StatusType(statusType) {
	case vc.StatusList2021VCStatus, vc.BitstringStatusList:
		purpose, ok := credentialStatusMap["statusPurpose"].(string)
		if !ok {
			return "", "", fmt.Errorf("statusPurpose not found for type %s", statusType)
		}

		return statusType, purpose, nil

	case vc.RevocationList2020VCStatus, vc.RevocationList2021VCStatus:
		return statusType, statustype.DefaultStatusPurpose, nil

	default:
		return "", "", fmt.Errorf("unsupported status type: %s", statusType)
	}
}
