/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc_devapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/cucumber/godog"
	"github.com/trustbloc/logutil-go/pkg/log"

	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

var logger = log.New("bdd-test")

type Steps struct {
	bddContext     *bddcontext.BDDContext
	responseStatus int
	responseBody   []byte
	credType       string
}

// NewSteps returns new Steps context.
func NewSteps(ctx *bddcontext.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers VC scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^I request did config for "([^"]*)" with ID "([^"]*)" and type "([^"]*)"$`, s.requestDidConfig)
	sc.Step(`^I receive response with status code "([^"]*)" for didconfig$`, s.checkResponseStatus)
}

func (s *Steps) checkResponseStatus(status string) error {
	code, err := strconv.Atoi(status)
	if err != nil {
		return fmt.Errorf("invalid status: %w", err)
	}

	logger.Info("Checking response status", log.WithHTTPStatus(s.responseStatus))

	if s.responseStatus != code {
		return fmt.Errorf("expected %d, got %d", code, s.responseStatus)
	}

	return nil
}

func (s *Steps) requestDidConfig(profileType string, id string, credType string) error {
	s.credType = credType

	url := fmt.Sprintf("http://localhost:8075/%s/profiles/%s/well-known/did-config",
		profileType, id)

	return s.httpGet(url, true)
}

func (s *Steps) httpGet(url string, withAuth bool) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)

	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if withAuth {
		req.Header.Add("X-API-Key", "rw_token")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error("Failed to close response body", log.WithError(closeErr))
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	s.responseBody = body
	s.responseStatus = resp.StatusCode

	logger.Info("vc_devapi httpGet content", log.WithResponse(body), log.WithHTTPStatus(s.responseStatus))

	return nil
}
