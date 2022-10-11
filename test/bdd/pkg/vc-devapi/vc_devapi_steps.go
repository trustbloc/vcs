package vc_devapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

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
	sc.Step(`^I request did config for "([^"]*)" with ID "([^"]*)" and type "([^"]*)"$`, s.requestDidConfig)
	sc.Step(`^I receive response with status code "([^"]*)" for didconfig$`, s.checkResponseStatus)

	sc.Step(`^I request object store with "([^"]*)"$`, s.requestObjectStore)
	sc.Step(`^I receive response for object-store with status code "([^"]*)" and body "([^"]*)"$`, s.checkObjectStoreResponse)
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

func (s *Steps) requestObjectStore(uuid string) error {
	url := fmt.Sprintf("http://localhost:8075/request-object/%v",
		uuid)

	return s.httpGet(url, false)
}

func (s *Steps) checkObjectStoreResponse(statusCode string, body string) error {
	code, err := strconv.Atoi(statusCode)
	if err != nil {
		return fmt.Errorf("invalid status: %w", err)
	}

	if s.responseStatus != code {
		return errors.New(fmt.Sprintf("invalid code. expected %v got %v", statusCode, s.responseStatus))
	}

	if strings.EqualFold(string(s.responseBody), body) {
		return errors.New(fmt.Sprintf("invalid body. expected %v got %v", body, string(s.responseBody)))
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
