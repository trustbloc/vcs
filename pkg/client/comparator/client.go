/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package comparator

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/openapi"
)

const (
	configEndpoint  = "/config"
	compareEndpoint = "/compare"
)

var logger = log.New("comparator-client")

// Client for comparator
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// New return new instance of comparator client
func New(baseURL string, opts ...Option) *Client {
	c := &Client{httpClient: &http.Client{}, baseURL: baseURL}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Compare compare docs
func (c *Client) Compare(cr openapi.Comparison) (bool, error) { //nolint: interfacer
	reqBytes, err := cr.MarshalJSON()
	if err != nil {
		return false, err
	}

	target := c.baseURL + compareEndpoint

	req, err := http.NewRequest(http.MethodPost, target, bytes.NewBuffer(reqBytes))
	if err != nil {
		return false, err
	}

	resp, err := c.sendHTTPRequest(req, http.StatusOK)
	if err != nil {
		return false, err
	}

	var comp openapi.ComparisonResult
	if err := json.Unmarshal(resp, &comp); err != nil {
		return false, fmt.Errorf("failed to unmarshal resp to comparator compare result: %w", err)
	}

	return comp.Result, nil
}

// GetConfig get comparator config
func (c *Client) GetConfig() (*openapi.Config, error) {
	target := c.baseURL + configEndpoint

	req, err := http.NewRequest(http.MethodPost, target, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.sendHTTPRequest(req, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var cof openapi.Config
	if err := json.Unmarshal(resp, &cof); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp to comparator config: %w", err)
	}

	return &cof, nil
}

func (c *Client) sendHTTPRequest(req *http.Request, status int) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close response body")
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("failed to read response body for status %d: %s", resp.StatusCode, err)
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("failed to read response body for status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// Option is a csh client instance option
type Option func(opts *Client)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Client) {
		opts.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
}
