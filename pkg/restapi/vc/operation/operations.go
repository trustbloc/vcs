/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
)

const (
	createCredentialEndpoint = "/credential"
	credentialContext        = "https://www.w3.org/2018/credentials/v1"
	// ID is the identifier for the verifiable credential
	ID = "https://example.com/credentials/1872"
	// TODO create the profile and get the prefix of the ID from the profile issue-47
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// New returns CreateCrendential instance
func New() *Operation {
	svc := &Operation{}
	svc.registerHandler()

	return svc
}

// Operation defines handlers for VC service
type Operation struct {
	handlers []Handler
}

func (c *Operation) createCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	data := CreateCrendential{}
	err := json.NewDecoder(req.Body).Decode(&data)

	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		_, err = rw.Write([]byte(fmt.Sprintf("Receieved invalid request: %s", err.Error())))

		if err != nil {
			log.Errorf("Failed to write response for credential creation failure (unable to read request): %s", err.Error())
		}

		return
	}

	validCredential, err := createCredential(&data)

	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		_, err = rw.Write([]byte(fmt.Sprintf("validation failed for vc: %s", err.Error())))

		if err != nil {
			log.Errorf("Failed to write response for create credential failure: %s", err.Error())
		}

		return
	}

	c.writeResponse(rw, validCredential)
}

// writeResponse writes interface value to response
func (c *Operation) writeResponse(rw http.ResponseWriter, v interface{}) {
	rw.WriteHeader(http.StatusCreated)
	err := json.NewEncoder(rw).Encode(v)
	// as of now, just log errors for writing response
	if err != nil {
		log.Errorf("Unable to send error response, %s", err)
	}
}
func createCredential(data *CreateCrendential) (*verifiable.Credential, error) {
	credential := &verifiable.Credential{}
	issueDate := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(),
		time.Now().Hour(), time.Now().Minute(), time.Now().Second(), 0, time.UTC)

	credential.Context = []string{credentialContext}
	credential.Subject = data.Subject
	credential.Types = data.Type
	credential.Issuer = data.Issuer
	credential.Issued = &issueDate
	credential.ID = ID

	cred, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("create credential marshalling failed: %s", err.Error())
	}

	validatedCred, _, err := verifiable.NewCredential(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to create new credential: %s", err.Error())
	}

	return validatedCred, nil
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(createCredentialEndpoint, http.MethodPost, c.createCredentialHandler),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}
