/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cucumber/godog"
	"github.com/tidwall/gjson"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
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
func (e *Steps) RegisterSteps(s *godog.ScenarioContext) {
	s.Step(`^we wait (\d+) seconds$`, e.wait)
	s.Step(`^an HTTP GET is sent to "([^"]*)"$`, e.httpGet)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)"$`, e.httpPost)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)" and the returned status code is (\d+)$`, e.httpPostWithExpectedCode)
	s.Step(`^the JSON path "([^"]*)" of the response equals "([^"]*)"$`, e.jsonPathOfCCResponseEquals)
}

func (e *Steps) wait(seconds int) error {
	time.Sleep(time.Duration(seconds) * time.Second)

	return nil
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
			logger.Warn("Error closing HTTP response", log.WithURL(url), log.WithError(errClose))
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

func (e *Steps) httpPost(url, data, contentType string) error {
	resp, err := e.doHTTPPost(url, []byte(data), contentType)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d: %s", resp.StatusCode, resp.ErrorMsg)
	}

	return nil
}

func (e *Steps) httpPostWithExpectedCode(url, data, contentType string, expectingCode int) error {
	resp, err := e.doHTTPPost(url, []byte(data), contentType)
	if err != nil {
		return err
	}

	if resp.StatusCode != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, resp.StatusCode)
	}

	return nil
}

type httpResponse struct {
	Payload    []byte
	ErrorMsg   string
	StatusCode int
	Header     http.Header
}

func (e *Steps) doHTTPPost(url string, content []byte, contentType string) (*httpResponse, error) {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: e.bddContext.TLSConfig}}
	defer client.CloseIdleConnections()

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(content))
	if err != nil {
		return nil, err
	}

	logger.Info(fmt.Sprintf("Sending POST to url[%s] for content-type[%s] with content[%s]", url, contentType, string(content)))

	httpReq.Header.Set("Content-Type", contentType)
	httpReq.Header.Add("X-API-Key", "rw_token")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warn(fmt.Sprintf("Error closing HTTP response from [%s]: %s", url, err))
		}
	}()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Info(fmt.Sprintf("Error reading response body from [%s]: %s", url, err))
	}

	if resp.StatusCode != http.StatusOK {
		return &httpResponse{
			StatusCode: resp.StatusCode,
			Header:     resp.Header,
			ErrorMsg:   string(payload),
		}, nil
	}

	return &httpResponse{
		Payload:    payload,
		StatusCode: http.StatusOK,
		Header:     resp.Header,
	}, nil
}

func (e *Steps) jsonPathOfCCResponseEquals(path, expected string) error {
	r := gjson.Get(e.queryValue, path)

	logger.Info("JSON path resolution", log.WithPath(path), logfields.WithJSONQuery(e.queryValue), logfields.WithJSONResolution(r.Str))

	if r.Str == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", r.Str, expected)
}
