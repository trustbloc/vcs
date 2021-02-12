/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

const (
	getDocMetadataPath = "/vaults/%s/docs/%s/metadata"
)

var logger = log.New("vault-client")

// Client for vault
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// New return new instance of vault client
func New(baseURL string, opts ...Option) *Client {
	c := &Client{httpClient: &http.Client{}, baseURL: baseURL}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetDocMetaData get doc metadata
func (c *Client) GetDocMetaData(vaultID, docID string) (*vault.DocumentMetadata, error) {
	target := c.baseURL + fmt.Sprintf(getDocMetadataPath, vaultID, docID)

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.sendHTTPRequest(req, http.StatusCreated)
	if err != nil {
		return nil, err
	}

	var docMeta vault.DocumentMetadata
	if err := json.Unmarshal(resp, &docMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp to vault doc meta: %w", err)
	}

	return &docMeta, nil
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

// Option is a vault client instance option
type Option func(opts *Client)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Client) {
		opts.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
}
