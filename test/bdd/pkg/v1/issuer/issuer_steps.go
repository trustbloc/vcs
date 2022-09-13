/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/context"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

const (
	issuerURL              = "http://localhost:8075"
	issuerProfileURL       = issuerURL + "/issuer/profiles"
	issuerProfileURLFormat = issuerProfileURL + "/%s"
)

func getProfileIDKey(user string) string {
	return user + "-profileID"
}

func getProfileAuthToken(user string) string {
	// temporary we use org id as token
	return user + "-userOrg"
}

var logger = log.New("bdd-test")

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
	s.Step(`^"([^"]*)" sends request to create an issuer profile with the organization "([^"]*)"$`, e.createIssuerProfile)
	s.Step(`^"([^"]*)" deactivates the issuer profile$`, e.deactivateIssuerProfile)
	s.Step(`^"([^"]*)" activates the issuer profile$`, e.activateIssuerProfile)
	s.Step(`^"([^"]*)" deletes the issuer profile$`, e.deleteIssuerProfile)
	s.Step(`^"([^"]*)" updates the issuer profile name to "([^"]*)"$`, e.updateIssuerProfileName)

	s.Step(`^"([^"]*)" can recreate the issuer profile with the organization "([^"]*)"$`, e.createIssuerProfile)
}

func (e *Steps) createIssuerProfile(user, organizationName string) error { //nolint: funlen
	profileRequest := model.CreateIssuerProfileData{
		Name:           "Test",
		OidcConfig:     nil,
		OrganizationID: organizationName,
		Url:            "TestURL",
		VcConfig: model.VCConfig{
			Contexts:         nil,
			DidMethod:        "orb",
			Format:           "ldp_vc",
			KeyType:          "ED25519",
			SigningAlgorithm: "Ed25519Signature2018",
			Status:           nil,
		},
	}

	e.bddContext.Args[getProfileAuthToken(user)] = organizationName

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodPost, issuerProfileURL, "application/json",
		e.bddContext.Args[getProfileAuthToken(user)], //nolint: bodyclose
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
		return bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, respBytes)
	}

	profileResponse := model.IssuerProfile{}

	err = json.Unmarshal(respBytes, &profileResponse)
	if err != nil {
		return err
	}

	e.bddContext.Args[getProfileIDKey(user)] = profileResponse.Id

	return err
}

func (e *Steps) updateIssuerProfileName(user, profileName string) error {
	id := e.bddContext.Args[getProfileIDKey(user)]
	token := e.bddContext.Args[getProfileAuthToken(user)]

	profileRequest := model.UpdateIssuerProfileData{
		Name: profileName,
	}

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPDo(http.MethodDelete, fmt.Sprintf(issuerProfileURLFormat, //nolint: bodyclose
		id), "", token, bytes.NewBuffer(requestBytes))
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

func (e *Steps) deleteIssuerProfile(user string) error {
	err := e.doSimpleProfileIDRequest(user, http.MethodGet, issuerProfileURLFormat)
	if err != nil {
		return err
	}
	return e.doSimpleProfileIDRequest(user, http.MethodDelete, issuerProfileURLFormat)
}

func (e *Steps) activateIssuerProfile(user string) error {
	return e.doSimpleProfileIDRequest(user, http.MethodPost, issuerProfileURLFormat+"/activate")
}

func (e *Steps) deactivateIssuerProfile(user string) error {
	return e.doSimpleProfileIDRequest(user, http.MethodPost, issuerProfileURLFormat+"/deactivate")
}

func (e *Steps) doSimpleProfileIDRequest(user, httpMethod, urlFormat string) error {
	id := e.bddContext.Args[getProfileIDKey(user)]
	token := e.bddContext.Args[getProfileAuthToken(user)]

	print("ID: " + id)

	resp, err := bddutil.HTTPDo(httpMethod, fmt.Sprintf(urlFormat, id), "", token, nil)
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
