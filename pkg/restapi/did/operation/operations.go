/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/proxy/rules"
)

const (
	resolveURL = "/1.0/identifiers/{did}"

	// outbound headers
	contentTypeHeader = "Content-type"

	// inbound headers
	authorizationHeader = "Authorization"
	acceptHeader        = "Accept"

	// content type
	didLDJson = "application/did+ld+json"

	// DID methods supported by local implementations
	didMethodKey = "key"

	defaultTimeout = 240 * time.Second
)

var logger = log.New("edge-service-did-restapi")

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
		keyVDRI:      config.KeyVDRI,
		httpClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
	}

	return svc
}

// Config defines configuration for vcs operations
type Config struct {
	RuleProvider rules.Provider
	KeyVDRI      key.VDR
	TLSConfig    *tls.Config
}

// Operation defines handlers for DID REST service
type Operation struct {
	ruleProvider rules.Provider
	keyVDRI      key.VDR
	httpClient   httpClient
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(resolveURL, http.MethodGet, o.resolve),
	}
}

func (o *Operation) resolve(rw http.ResponseWriter, req *http.Request) {
	did := mux.Vars(req)["did"]

	logger.Debugf("resolve received request for DID: %s", did)

	destinationURL, err := o.ruleProvider.Transform(did)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to transform DID to destination URL: %s", err.Error()))
		return
	}

	if destinationURL == "" {
		o.resolveWithVDRI(rw, did)
		return
	}

	o.resolveWithProxy(rw, req, destinationURL)
}

func (o *Operation) resolveWithVDRI(rw http.ResponseWriter, didURI string) {
	did, err := diddoc.Parse(didURI)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid DID: %s", err.Error()))
		return
	}

	var docResolution *diddoc.DocResolution

	switch did.Method {
	case didMethodKey:
		docResolution, err = o.keyVDRI.Read(did.String())
		if err != nil {
			writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to resolve DID: %s", err.Error()))
			return
		}
	default:
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("unsupported DID method: %s", did.Method))
		return
	}

	bytes, err := docResolution.DIDDocument.JSONBytes()
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to convert DIDDoc to json bytes: %s", err.Error()))
		return
	}

	writeResponse(rw, http.StatusOK, didLDJson, bytes)
}

func (o *Operation) resolveWithProxy(rw http.ResponseWriter, req *http.Request, destinationURL string) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	newReq, err := http.NewRequest(http.MethodGet, destinationURL, nil)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to create new request: %s", err.Error()))
		return
	}

	addRequestHeaders(req, newReq)

	resp, err := o.httpClient.Do(newReq.WithContext(ctx))
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to proxy: %s", err.Error()))
		return
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

	logger.Debugf("proxy returning destination status '%d' and body: %s", resp.StatusCode, string(body))

	writeResponse(rw, resp.StatusCode, resp.Header.Get(contentTypeHeader), body)
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

func writeResponse(rw http.ResponseWriter, status int, contentType string, body []byte) {
	rw.Header().Add(contentTypeHeader, contentType)
	rw.WriteHeader(status)

	_, err := rw.Write(body)
	if err != nil {
		logger.Errorf("Unable to write response, %s", err)
	}
}

func writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	logger.Warnf("proxy returning status code: %d, error: %s", status, msg)

	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(errorResponse{
		Message: msg,
	})

	if err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// errorResponse to send error message in the response
type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}
