/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc_version

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/cucumber/godog"
	"github.com/trustbloc/logutil-go/pkg/log"

	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

var logger = log.New("bdd-test")

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
	sc.Step(`^I request Version$`, s.requestVersion)
	sc.Step(`^I request SystemVersion$`, s.requestSystemVersion)
	sc.Step(`^Version is set$`, s.checkResponseStatus)
}

func (s *Steps) requestVersion() error {
	return s.httpGet("http://localhost:8075/version")
}

func (s *Steps) requestSystemVersion() error {
	return s.httpGet("http://localhost:8075/version/system")
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

func (s *Steps) checkResponseStatus() error {
	if s.responseStatus != http.StatusOK {
		return fmt.Errorf("unexpected http status %v", s.responseStatus)
	}

	resp := struct {
		Version string `json:"version"`
	}{}

	if err := json.Unmarshal(s.responseBody, &resp); err != nil {
		return err
	}

	if resp.Version == "" {
		return errors.New("version should not be empty")
	}

	return nil
}
