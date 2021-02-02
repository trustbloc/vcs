/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"encoding/json"
	"net/http"

	"github.com/cucumber/godog"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

// Steps is steps for vault tests.
type Steps struct {
	bddContext *context.BDDContext
	client     *http.Client
}

// NewSteps returns new vault steps.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx, client: &http.Client{}}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Create a new vault using the vault server "([^"]*)"$`, e.createVault)
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

	return nil
}
