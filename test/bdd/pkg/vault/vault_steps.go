/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

// Steps is steps for vault tests.
type Steps struct {
	bddContext *context.BDDContext
	client     *http.Client
	vaultID    string
	vaultURL   string
}

// NewSteps returns new vault steps.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx, client: &http.Client{}}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Create a new vault using the vault server "([^"]*)"$`, e.createVault)
	s.Step(`^Save a document with the following id "([^"]*)"$`, e.saveDocument)
	s.Step(`^Check that a document with id "([^"]*)" is stored$`, e.getDocument)
}

func (e *Steps) createVault(endpoint string) error {
	resp, err := e.client.Post(endpoint+"/vaults", "", nil)
	if err != nil {
		return err
	}

	defer resp.Body.Close() // nolint: errcheck

	var result *vault.CreatedVault

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return err
	}

	if result.ID == "" {
		return errors.New("id is empty")
	}

	e.vaultID = result.ID
	e.vaultURL = endpoint

	return nil
}

func (e *Steps) saveDocument(docID string) error {
	endpoint := fmt.Sprintf("/vaults/%s/docs", url.QueryEscape(e.vaultID))

	resp, err := e.client.Post(e.vaultURL+endpoint, "", strings.NewReader(fmt.Sprintf(`{"id":%q}`, docID)))
	if err != nil {
		return err
	}

	defer resp.Body.Close() // nolint: errcheck

	var result *vault.DocumentMetadata

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return err
	}

	if result.ID == "" || result.URI == "" {
		return errors.New("result is empty")
	}

	return nil
}

func (e *Steps) getDocument(docID string) error {
	endpoint := fmt.Sprintf("/vaults/%s/docs/%s/metadata", url.QueryEscape(e.vaultID), docID)

	resp, err := e.client.Get(e.vaultURL + endpoint)
	if err != nil {
		return err
	}

	defer resp.Body.Close() // nolint: errcheck

	var result *vault.DocumentMetadata

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return err
	}

	if result.ID == "" || result.URI == "" {
		return errors.New("result is empty")
	}

	return nil
}
