/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-service/pkg/restapi/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/vault/operation"
)

const (
	saveDocPath              = "/vaults/%s/docs"
	getDocMetadataPath       = "/vaults/%s/docs/%s/metadata"
	getAuthorizationsPath    = "/vaults/%s/authorizations/%s"
	createAuthorizationsPath = "/vaults/%s/authorizations"
)

var logger = log.New("vault-client")

// HTTPClient interface for the http client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client for vault
type Client struct {
	httpClient HTTPClient
	baseURL    string
}

// New return new instance of vault client
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: time.Minute,
		},
		baseURL: baseURL,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// CreateVault creates a new vault.
func (c *Client) CreateVault() (*vault.CreatedVault, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+operation.CreateVaultPath, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := c.sendHTTPRequest(req, http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}

	var result vault.CreatedVault

	err = json.Unmarshal(resp, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshal to CreatedVault: %w", err)
	}

	return &result, nil
}

// SaveDoc saves a document.
func (c *Client) SaveDoc(vaultID, id string, content interface{}) (*vault.DocumentMetadata, error) {
	target := c.baseURL + fmt.Sprintf(saveDocPath, url.QueryEscape(vaultID))

	raw, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content: %w", err)
	}

	src, err := json.Marshal(operation.SaveDocRequestBody{
		ID:      id,
		Content: raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := c.sendHTTPRequest(req, http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}

	var result vault.DocumentMetadata

	err = json.Unmarshal(resp, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshal to DocumentMetadata: %w", err)
	}

	return &result, nil
}

// GetDocMetaData get doc metadata
func (c *Client) GetDocMetaData(vaultID, docID string) (*vault.DocumentMetadata, error) { // nolint: dupl
	target := c.baseURL + fmt.Sprintf(getDocMetadataPath, url.QueryEscape(vaultID), url.QueryEscape(docID))

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := c.sendHTTPRequest(req, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}

	var docMeta vault.DocumentMetadata
	if err := json.Unmarshal(resp, &docMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp to vault doc meta: %w", err)
	}

	return &docMeta, nil
}

// CreateAuthorization creates an authorization.
func (c *Client) CreateAuthorization(vaultID, requestingParty string,
	scope *vault.AuthorizationsScope) (*vault.CreatedAuthorization, error) {
	target := c.baseURL + fmt.Sprintf(createAuthorizationsPath, url.QueryEscape(vaultID))

	src, err := json.Marshal(operation.CreateAuthorizationsBody{
		RequestingParty: requestingParty,
		Scope:           *scope,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := c.sendHTTPRequest(req, http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}

	var result vault.CreatedAuthorization
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("unmarshal to CreatedAuthorization: %w", err)
	}

	return &result, nil
}

// GetAuthorization returns an authorization.
func (c *Client) GetAuthorization(vaultID, id string) (*vault.CreatedAuthorization, error) { // nolint: dupl
	target := c.baseURL + fmt.Sprintf(getAuthorizationsPath, url.QueryEscape(vaultID), url.QueryEscape(id))

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := c.sendHTTPRequest(req, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}

	var result vault.CreatedAuthorization
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("unmarshal to CreatedAuthorization: %w", err)
	}

	return &result, nil
}

func (c *Client) sendHTTPRequest(req *http.Request, status int) ([]byte, error) { // nolunt: dupl
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

// WithHTTPClient allows providing HTTP client.
func WithHTTPClient(c HTTPClient) Option {
	return func(opts *Client) {
		opts.httpClient = c
	}
}
