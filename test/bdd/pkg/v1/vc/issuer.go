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

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

const (
	issuerProfileURL         = credentialServiceURL + "/issuer/profiles"
	issuerProfileURLFormat   = issuerProfileURL + "/%s"
	issueCredentialURLFormat = issuerProfileURLFormat + "/credentials/issue"
)

func (e *Steps) createIssuerProfile(profileName, organizationName, signatureHolder, didMethod, signatureType,
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

	respBytes, err := io.ReadAll(resp.Body)
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

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, profileResponse.VcConfig.SigningDID, 10)
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) getIssuerProfileData(profileName string) (*model.IssuerProfile, error) {
	id := e.bddContext.Args[getProfileIDKey(profileName)]
	token := e.bddContext.Args[getProfileAuthToken(profileName)]

	resp, err := bddutil.HTTPDo(http.MethodGet, fmt.Sprintf(issuerProfileURLFormat, id), "", token, nil)
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

	profileResponse := &model.IssuerProfile{}

	err = json.Unmarshal(respBytes, profileResponse)
	if err != nil {
		return nil, err
	}

	return profileResponse, nil
}

func (e *Steps) checkIssuerProfile(profileName, did, signatureType string) error {
	profileResponse, err := e.getIssuerProfileData(profileName)
	if err != nil {
		return err
	}

	return e.checkIssuerProfileResponse(profileName, did, signatureType, profileResponse)
}

func (e *Steps) checkIssuerProfileResponse(expectedProfileResponseName, expectedProfileDIDMethod, expectedSignatureType string,
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
