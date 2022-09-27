/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

const (
	issuerURL              = "https://localhost:4455"
	issuerProfileURL       = issuerURL + "/issuer/profiles"
	issuerProfileURLFormat = issuerProfileURL + "/%s"
)

func getProfileIDKey(user string) string {
	return user + "-profileID"
}

func getProfileAuthTokenKey(user string) string {
	return user + "-accessToken"
}

// Steps is steps for VC BDD tests
type Steps struct {
	bddContext *bddcontext.BDDContext
	tlsConfig  *tls.Config
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *bddcontext.BDDContext) *Steps {
	return &Steps{
		bddContext: ctx,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.ScenarioContext) {
	s.Step(`^"([^"]*)" has been authorized with client id "([^"]*)" and secret "([^"]*)" to use vcs$`, e.authorizeUser)
	s.Step(`^"([^"]*)" sends request to create an issuer profile with the organization "([^"]*)"$`, e.createIssuerProfile)
	s.Step(`^"([^"]*)" deactivates the issuer profile$`, e.deactivateIssuerProfile)
	s.Step(`^"([^"]*)" activates the issuer profile$`, e.activateIssuerProfile)
	s.Step(`^"([^"]*)" deletes the issuer profile$`, e.deleteIssuerProfile)
	s.Step(`^"([^"]*)" updates the issuer profile name to "([^"]*)"$`, e.updateIssuerProfileName)
	s.Step(`^"([^"]*)" can recreate the issuer profile with the organization "([^"]*)"$`, e.createIssuerProfile)
}

func (e *Steps) authorizeUser(user, clientID, secret string) error {
	accessToken, err := bddutil.IssueAccessToken(context.Background(), clientID, secret, []string{"org_admin"})
	if err != nil {
		return err
	}

	e.bddContext.Args[getProfileAuthTokenKey(user)] = accessToken

	return nil
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
			KeyType:          "ECDSAP256DER",
			SigningAlgorithm: "JsonWebSignature2020",
			Status:           nil,
		},
	}

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPSDo(http.MethodPost, issuerProfileURL, "application/json",
		e.bddContext.Args[getProfileAuthTokenKey(user)], //nolint: bodyclose
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
	token := e.bddContext.Args[getProfileAuthTokenKey(user)]

	profileRequest := model.UpdateIssuerProfileData{
		Name: profileName,
	}

	requestBytes, err := json.Marshal(profileRequest)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPSDo(http.MethodDelete, fmt.Sprintf(issuerProfileURLFormat, //nolint: bodyclose
		id), "", token, bytes.NewBuffer(requestBytes), e.tlsConfig)
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
	token := e.bddContext.Args[getProfileAuthTokenKey(user)]

	resp, err := bddutil.HTTPSDo(httpMethod, fmt.Sprintf(urlFormat, id), "", token, nil, e.tlsConfig)
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
