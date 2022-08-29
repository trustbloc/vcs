/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"text/template"

	"github.com/cucumber/godog"
	"github.com/google/go-cmp/cmp"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	bddcontext "github.com/trustbloc/vcs/test/bdd/pkg/context"
)

const (
	contentType     = "Content-Type"
	applicationJSON = "application/json"
	host            = "http://localhost:8075"
)

var (
	//go:embed testdata/verifier_profile_create.json
	verifierProfileCreateJSON []byte
	//go:embed testdata/verifier_profile_created.json
	verifierProfileCreatedJSON []byte
	//go:embed testdata/verifier_profile_update.json
	verifierProfileUpdateJSON []byte
	//go:embed testdata/verifier_profile_updated.json
	verifierProfileUpdatedJSON []byte
)

var logger = log.New("bdd-test")

// Steps defines context for Verifier profile management scenario steps.
type Steps struct {
	bddContext     *bddcontext.BDDContext
	httpClient     *http.Client
	responseStatus int
	responseBody   []byte
	profileID      string
	testdata       map[string][]byte
}

// NewSteps returns new Steps context.
func NewSteps(ctx *bddcontext.BDDContext) *Steps {
	httpClient := http.DefaultClient

	if os.Getenv("HTTP_CLIENT_TRACE_ON") == "true" {
		httpClient.Transport = &DumpTransport{r: http.DefaultTransport}
	}

	return &Steps{
		bddContext: ctx,
		httpClient: httpClient,
		testdata: map[string][]byte{
			"verifier_profile_create.json":  verifierProfileCreateJSON,
			"verifier_profile_created.json": verifierProfileCreatedJSON,
			"verifier_profile_update.json":  verifierProfileUpdateJSON,
			"verifier_profile_updated.json": verifierProfileUpdatedJSON,
		},
	}
}

// RegisterSteps registers scenario steps.
func (s *Steps) RegisterSteps(sc *godog.ScenarioContext) {
	sc.Step(`^organization "([^"]*)" creates a verifier profile with data from "([^"]*)"$`, s.createProfile)
	sc.Step(`^organization "([^"]*)" has a verifier profile with data from "([^"]*)"$`, s.createProfile)
	sc.Step(`^organization "([^"]*)" gets a verifier profile by ID$`, s.getProfileByID)
	sc.Step(`^organization "([^"]*)" updates a verifier profile with data from "([^"]*)"$`, s.updateProfile)
	sc.Step(`^organization "([^"]*)" deletes a verifier profile$`, s.deleteProfile)
	sc.Step(`^organization "([^"]*)" activates a verifier profile$`, s.activateProfile)
	sc.Step(`^organization "([^"]*)" deactivates a verifier profile$`, s.deactivateProfile)
	sc.Step(`^verifier profile is created$`, s.checkProfileCreated)
	sc.Step(`^verifier profile is updated$`, s.checkProfileUpdated)
	sc.Step(`^verifier profile is returned$`, s.checkProfileReturned)
	sc.Step(`^verifier profile is deleted$`, s.checkProfileDeleted)
	sc.Step(`^verifier profile is activated$`, s.checkProfileActivated)
	sc.Step(`^verifier profile is deactivated$`, s.checkProfileDeactivated)
	sc.Step(`^verifier profile matches "([^"]*)"$`, s.checkProfileMatches)
}

func (s *Steps) createProfile(ctx context.Context, orgID, content string) error {
	var profile verifierProfile

	if err := s.httpDo(ctx, http.MethodPost, host+"/verifier/profiles",
		withBody(bytes.NewReader(s.testdata[content])),
		withParsedResponse(&profile),
	); err != nil {
		return fmt.Errorf("create verifier profile: %w", err)
	}

	s.profileID = profile.ID

	return nil
}

func (s *Steps) getProfileByID(ctx context.Context, orgID string) error {
	var profile verifierProfile

	if err := s.httpDo(ctx, http.MethodGet, host+"/verifier/profiles/"+s.profileID,
		withParsedResponse(&profile),
	); err != nil {
		return fmt.Errorf("get verifier profile: %w", err)
	}

	s.profileID = profile.ID

	return nil
}

func (s *Steps) updateProfile(ctx context.Context, orgID, content string) error {
	var profile verifierProfile

	if err := s.httpDo(ctx, http.MethodPut, host+"/verifier/profiles/"+s.profileID,
		withBody(bytes.NewReader(s.testdata[content])),
		withParsedResponse(&profile),
	); err != nil {
		return fmt.Errorf("update verifier profile: %w", err)
	}

	s.profileID = profile.ID

	return nil
}

func (s *Steps) deleteProfile(ctx context.Context, orgID string) error {
	if err := s.httpDo(ctx, http.MethodDelete, host+"/verifier/profiles/"+s.profileID); err != nil {
		return fmt.Errorf("delete verifier profile: %w", err)
	}

	return nil
}

func (s *Steps) activateProfile(ctx context.Context, orgID string) error {
	if err := s.httpDo(ctx, http.MethodPost, host+"/verifier/profiles/"+s.profileID+"/activate"); err != nil {
		return fmt.Errorf("activate verifier profile: %w", err)
	}

	return nil
}

func (s *Steps) deactivateProfile(ctx context.Context, orgID string) error {
	if err := s.httpDo(ctx, http.MethodPost, host+"/verifier/profiles/"+s.profileID+"/deactivate"); err != nil {
		return fmt.Errorf("deactivate verifier profile: %w", err)
	}

	return nil
}

func (s *Steps) checkProfileCreated() error {
	return s.checkResponseStatus(http.StatusOK)
}

func (s *Steps) checkProfileUpdated() error {
	return s.checkResponseStatus(http.StatusOK)
}

func (s *Steps) checkProfileReturned() error {
	return s.checkResponseStatus(http.StatusOK)
}

func (s *Steps) checkProfileDeleted(ctx context.Context) error {
	if err := s.checkResponseStatus(http.StatusOK); err != nil {
		return err
	}

	if err := s.httpDo(ctx, http.MethodGet, host+"/verifier/profiles/"+s.profileID); err != nil {
		if err.Error() != "404 Not Found" {
			return err
		}
	}

	return nil
}

func (s *Steps) checkProfileActivated(ctx context.Context) error {
	if err := s.checkResponseStatus(http.StatusOK); err != nil {
		return err
	}

	var profile verifierProfile

	if err := s.httpDo(ctx, http.MethodGet, host+"/verifier/profiles/"+s.profileID,
		withParsedResponse(&profile),
	); err != nil {
		return err
	}

	if !profile.Active {
		return errors.New("verifier profile is not active")
	}

	return nil
}

func (s *Steps) checkProfileDeactivated(ctx context.Context) error {
	if err := s.checkResponseStatus(http.StatusOK); err != nil {
		return err
	}

	var profile verifierProfile

	if err := s.httpDo(ctx, http.MethodGet, host+"/verifier/profiles/"+s.profileID,
		withParsedResponse(&profile),
	); err != nil {
		return err
	}

	if profile.Active {
		return errors.New("verifier profile is active")
	}

	return nil
}

func (s *Steps) checkResponseStatus(code int) error {
	if s.responseStatus != code {
		return fmt.Errorf("got %d", s.responseStatus)
	}

	return nil
}

func (s *Steps) checkProfileMatches(content string) error {
	t, err := template.New("").Parse(string(s.testdata[content]))
	if err != nil {
		return fmt.Errorf("parse profile template: %w", err)
	}

	var buf bytes.Buffer

	err = t.Execute(&buf, s)
	if err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	var expected verifierProfile
	if err = json.Unmarshal(buf.Bytes(), &expected); err != nil {
		return fmt.Errorf("unmarshal expected profile: %w", err)
	}

	var actual verifierProfile
	if err = json.Unmarshal(s.responseBody, &actual); err != nil {
		return fmt.Errorf("unmarshal actual profile: %w", err)
	}

	if diff := cmp.Diff(expected, actual); diff != "" {
		return fmt.Errorf("mismatch (-want +got):\n%v", diff)
	}

	return nil
}

type options struct {
	body           io.Reader
	parsedResponse interface{}
}

type opt func(*options)

func withBody(body io.Reader) opt {
	return func(o *options) {
		o.body = body
	}
}

func withParsedResponse(v interface{}) opt {
	return func(o *options) {
		o.parsedResponse = v
	}
}

func (s *Steps) httpDo(ctx context.Context, method, url string, opts ...opt) error {
	op := &options{
		body: http.NoBody,
	}

	for _, fn := range opts {
		fn(op)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, op.body)
	if err != nil {
		return fmt.Errorf("create new request: %w", err)
	}

	req.Header.Add(contentType, applicationJSON)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	s.responseStatus = resp.StatusCode

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if len(respBody) > 0 {
		s.responseBody = respBody

		if resp.StatusCode != http.StatusOK {
			return parseError(resp.Status, respBody)
		}

		if op.parsedResponse != nil {
			if err = json.Unmarshal(respBody, op.parsedResponse); err != nil {
				return fmt.Errorf("unmarshal response body: %w", err)
			}
		}
	}

	return nil
}

type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

func parseError(status string, body []byte) error {
	var errResp errorResponse

	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Message != "" {
		return errors.New(errResp.Message)
	}

	return fmt.Errorf("%s", status)
}

// ProfileID is a helper function used in template to get the current profile ID.
func (s *Steps) ProfileID() string {
	return s.profileID
}

// DumpTransport is http.RoundTripper that dumps requests and responses.
type DumpTransport struct {
	r http.RoundTripper
}

// RoundTrip implements the RoundTripper interface.
func (d *DumpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump request: %w", err)
	}

	fmt.Printf("\n****REQUEST****\n%s\n\n", string(reqDump))

	resp, err := d.r.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump response: %w", err)
	}

	fmt.Printf("****RESPONSE****\n%s****************\n", string(respDump))

	return resp, nil
}
