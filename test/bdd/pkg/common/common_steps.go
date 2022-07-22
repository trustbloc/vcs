/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/tidwall/gjson"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/vcs/test/bdd/pkg/context"
)

var logger = log.New("common-steps")

// Steps is steps for VC BDD tests.
type Steps struct {
	bddContext *context.BDDContext
	queryValue string
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers agent steps.
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^an HTTP GET is sent to "([^"]*)"$`, e.httpGet)
	s.Step(`^the JSON path "([^"]*)" of the response equals "([^"]*)"$`, e.jsonPathOfCCResponseEquals)
}

// httpGet sends a GET request to the given URL.
func (e *Steps) httpGet(url string) error {
	e.queryValue = ""

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: e.bddContext.TLSConfig}}
	defer client.CloseIdleConnections()

	httpReq, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}

	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			logger.Warnf("Error closing HTTP response from [%s]: %s", url, errClose)
		}
	}()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body failed: %w", err)
	}

	e.queryValue = string(payload)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d", resp.StatusCode)
	}

	return nil
}

func (e *Steps) jsonPathOfCCResponseEquals(path, expected string) error {
	r := gjson.Get(e.queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, e.queryValue, r.Str)

	if r.Str == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", r.Str, expected)
}
