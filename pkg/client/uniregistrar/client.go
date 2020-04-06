/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package uniregistrar

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	didmethodoperation "github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
)

// Client for uni-registrar
type Client struct {
	httpClient *http.Client
}

// New return new instance of uni-registrar client
func New(opts ...Option) *Client {
	c := &Client{httpClient: &http.Client{}}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// CreateDID create did
func (c *Client) CreateDID(driverURL string, opts ...CreateDIDOption) (string, []didmethodoperation.Key, error) {
	createDIDOpts := &CreateDIDOpts{}

	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	jobID := uuid.New().String()

	reqBytes, err := json.Marshal(didmethodoperation.RegisterDIDRequest{JobID: jobID,
		AddPublicKeys: createDIDOpts.publicKeys, Options: createDIDOpts.options})
	if err != nil {
		return "", nil, err
	}

	req, err := http.NewRequest(http.MethodPost, driverURL, bytes.NewBuffer(reqBytes))
	if err != nil {
		return "", nil, err
	}

	resp, err := c.sendHTTPRequest(req, http.StatusOK)
	if err != nil {
		return "", nil, err
	}

	var registerResponse didmethodoperation.RegisterResponse
	if err := json.Unmarshal(resp, &registerResponse); err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal resp to register response: %w", err)
	}

	if registerResponse.JobID != "" && jobID != registerResponse.JobID {
		return "", nil, fmt.Errorf("register response jobID=%s not equal %s", registerResponse.JobID, jobID)
	}

	if registerResponse.DIDState.State == didmethodoperation.RegistrationStateFailure {
		return "", nil, fmt.Errorf("failure from uniregistrar %s", registerResponse.DIDState.Reason)
	}

	if registerResponse.DIDState.State != didmethodoperation.RegistrationStateFinished {
		return "", nil, fmt.Errorf("uniregistrar return unknown state %s", registerResponse.DIDState.State)
	}

	return registerResponse.DIDState.Identifier, registerResponse.DIDState.Secret.Keys, nil
}

func (c *Client) sendHTTPRequest(req *http.Request, status int) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Warn("failed to close response body")
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Warnf("failed to read response body for status %d: %s", resp.StatusCode, err)
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("failed to read response body for status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// Option is a uniregistrar client instance option
type Option func(opts *Client)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Client) {
		opts.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
}

// CreateDIDOpts create did opts
type CreateDIDOpts struct {
	publicKeys []didmethodoperation.PublicKey
	options    map[string]string
}

// CreateDIDOption is a create DID option
type CreateDIDOption func(opts *CreateDIDOpts)

// WithPublicKey add DID public key
func WithPublicKey(publicKey didmethodoperation.PublicKey) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.publicKeys = append(opts.publicKeys, publicKey)
	}
}

// WithOptions add option
func WithOptions(options map[string]string) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.options = options
	}
}
