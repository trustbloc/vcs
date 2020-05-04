/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/proxy/rules"
)

const (
	proxyURL = "/1.0/identifiers/{did}"

	// outbound headers
	contentTypeHeader = "Content-type"

	// inbound headers
	authorizationHeader = "Authorization"
	acceptHeader        = "Accept"
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// New returns new did proxy instance
func New(config *Config) *Operation {
	svc := &Operation{
		ruleProvider: config.RuleProvider,
		httpClient:   &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
	}

	return svc
}

// Config defines configuration for vcs operations
type Config struct {
	TLSConfig    *tls.Config
	RuleProvider rules.Provider
}

// Operation defines handlers for DID REST service
type Operation struct {
	ruleProvider rules.Provider
	httpClient   httpClient
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(proxyURL, http.MethodGet, o.proxy),
	}
}

// Proxy will proxy requests based on provided configuration
func (o *Operation) proxy(rw http.ResponseWriter, req *http.Request) {
	did := mux.Vars(req)["did"]

	log.Debugf("proxy received request for DID: %s", did)

	destinationURL, err := o.ruleProvider.Transform(did)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to transform DID to destination URL: %s", err.Error()))
		return
	}

	log.Debugf("proxy resolved DID '%s' to destination URL '%s'", did, destinationURL)

	newReq, err := http.NewRequest(http.MethodGet, destinationURL, nil)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to create new request: %s", err.Error()))
		return
	}

	addRequestHeaders(req, newReq)

	resp, err := o.httpClient.Do(newReq)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to proxy: %s", err.Error()))

		return
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

	log.Debugf("proxy returning destination status '%d' and body: %s", resp.StatusCode, string(body))

	rw.Header().Add(contentTypeHeader, resp.Header.Get(contentTypeHeader))
	rw.WriteHeader(resp.StatusCode)

	_, err = rw.Write(body)
	if err != nil {
		log.Errorf("Unable to write response, %s", err)
	}
}

func addRequestHeaders(req, newReq *http.Request) {
	allowedHeaders := []string{acceptHeader, authorizationHeader}

	for _, header := range allowedHeaders {
		value := req.Header.Get(header)
		if value != "" {
			newReq.Header.Add(header, value)
		}
	}
}

func (o *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	log.Warnf("proxy returning status code: %d, error: %s", status, msg)

	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(ErrorResponse{
		Message: msg,
	})

	if err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
}

// ErrorResponse to send error message in the response
type ErrorResponse struct {
	Message string `json:"errMessage,omitempty"`
}
