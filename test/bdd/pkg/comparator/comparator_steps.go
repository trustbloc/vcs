/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comparator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cucumber/godog"

	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation"
	"github.com/trustbloc/edge-service/test/bdd/pkg/bddutil"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	comparatorURL = "https://localhost:8065"
)

// Steps is steps for BDD tests
type Steps struct {
	bddContext *context.BDDContext
}

// NewSteps returns new steps
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Check comparator config is created`, e.checkConfig)
}

func (e *Steps) checkConfig() error {
	url := comparatorURL + "/config"

	resp, err := bddutil.HTTPSDo(http.MethodPost, url, "", //nolint: bodyclose
		"", bytes.NewBuffer(nil), e.bddContext.TLSConfig)
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

	var cc operation.ComparatorConfig
	if err := json.Unmarshal(respBytes, &cc); err != nil {
		return err
	}

	if cc.DID == "" {
		return fmt.Errorf("comparator config DID is empty")
	}

	return nil
}
