package vc_devapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

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
	sc.Step(`^I request did config for "([^"]*)" with ID "([^"]*)" and type "([^"]*)"$`, s.httpGet)
	sc.Step(`^I receive response with status code "([^"]*)" for didconfig$`, s.checkResponseStatus)
}

func (s *Steps) checkResponseStatus(status string) error {
	code, err := strconv.Atoi(status)
	if err != nil {
		return fmt.Errorf("invalid status: %w", err)
	}

	logger.Infof("checking response status %v", s.responseStatus)

	if s.responseStatus != code {
		return fmt.Errorf("expected %d, got %d", code, s.responseStatus)
	}

	return nil
}

func (s *Steps) httpGet(profileType string, id string, credType string) error {
	s.credType = credType

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		fmt.Sprintf("http://localhost:8075/%s/profiles/%s/well-known/did-config",
			profileType, id), http.NoBody)

	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("X-API-Key", "rw_token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	s.responseBody = body
	s.responseStatus = resp.StatusCode

	logger.Infof("body : %v and status %v", string(body), s.responseStatus)

	return nil
}
