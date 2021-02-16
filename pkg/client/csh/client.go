/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package csh

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
)

const (
	profilesEndpoint = "/hubstore/profiles"
)

var logger = log.New("csh-client")

// Client for csh
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// New return new instance of csh client
func New(baseURL string, opts ...Option) *Client {
	c := &Client{httpClient: &http.Client{}, baseURL: baseURL}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// CreateProfile create csh profile
func (c *Client) CreateProfile(controller string) (*openapi.Profile, error) {
	reqBytes, err := json.Marshal(&openapi.Profile{
		Controller: &controller,
	})
	if err != nil {
		return nil, err
	}

	target := c.baseURL + profilesEndpoint

	req, err := http.NewRequest(http.MethodPost, target, bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, err
	}

	resp, err := c.sendHTTPRequest(req, http.StatusCreated)
	if err != nil {
		return nil, err
	}

	var profile openapi.Profile
	if err := json.Unmarshal(resp, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp to csh profile: %w", err)
	}

	return &profile, nil
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
