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

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

const (
	verifierProfileURL        = credentialServiceURL + "/verifier/profiles"
	verifierProfileURLFormat  = verifierProfileURL + "/%s"
	verifyCredentialURLFormat = verifierProfileURLFormat + "/credentials/verify"
)

func (e *Steps) createVerifierProfile(profileName, organizationName string) error {
	url := issuerProfileURL
	verifierProfileRequest := model.CreateVerifierProfileData{
		Checks: map[string]interface{}{
			"credential": map[string]interface{}{
				"format": []string{
					"ldp_vc",
				},
				"proof":  true,
				"status": false,
			},
		},
		Name:           profileName,
		OidcConfig:     nil,
		OrganizationID: organizationName,
		Url:            &url,
	}

	requestBytes, err := json.Marshal(verifierProfileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPSDo(http.MethodPost, verifierProfileURL, "application/json",
		e.bddContext.Args[getOrgAuthTokenKey(organizationName)], //nolint: bodyclose
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
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	verifierProfileResponse := model.VerifierProfile{}

	err = json.Unmarshal(respBytes, &verifierProfileResponse)
	if err != nil {
		return err
	}

	e.bddContext.Args[getProfileIDKey(profileName)] = verifierProfileResponse.ID

	return nil
}

func (e *Steps) getVerifierProfileData(profileName, organizationName string) (*model.VerifierProfile, error) {
	id := e.bddContext.Args[getProfileIDKey(profileName)]
	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]

	resp, err := bddutil.HTTPSDo(http.MethodGet, fmt.Sprintf(verifierProfileURLFormat, id), "", token, nil, e.tlsConfig)
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

	verifierProfileResponse := &model.VerifierProfile{}

	err = json.Unmarshal(respBytes, verifierProfileResponse)
	if err != nil {
		return nil, err
	}

	return verifierProfileResponse, nil
}

func (e *Steps) checkVerifierProfile(profileName, organizationName string) error {
	profileResponse, err := e.getVerifierProfileData(profileName, organizationName)
	if err != nil {
		return err
	}

	return e.checkVerifierProfileResponse(profileName, profileResponse)
}

func (e *Steps) checkVerifierProfileResponse(expectedProfileResponseName string,
	profileResponse *model.VerifierProfile) error {
	if profileResponse.Name != expectedProfileResponseName {
		return fmt.Errorf("expected %s but got %s instead", expectedProfileResponseName, profileResponse.Name)
	}

	return nil
}
