/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc_echo

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

// Steps defines context for VC scenario steps.
type Steps struct {
	bddContext     *bddcontext.BDDContext
	responseStatus int
	responseBody   []byte
}

// NewSteps returns new Steps context.
func NewSteps(ctx *bddcontext.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers VC scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^I make an HTTP GET to "([^"]*)"$`, s.httpGet)
	sc.Step(`^I receive response with status code "([^"]*)"$`, s.checkResponseStatus)
}

func (s *Steps) httpGet(url string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
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

	s.responseStatus = resp.StatusCode

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	s.responseBody = body

	return nil
}

func (s *Steps) checkResponseStatus(status string) error {
	code, err := strconv.Atoi(status)
	if err != nil {
		return fmt.Errorf("invalid status: %w", err)
	}

	if s.responseStatus != code {
		return fmt.Errorf("expected %d, got %d", code, s.responseStatus)
	}

	return nil
}
