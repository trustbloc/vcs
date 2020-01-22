/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	log "github.com/sirupsen/logrus"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
)

const (
	credentialStore   = "credential"
	credentialContext = "https://www.w3.org/2018/credentials/v1"

	// endpoints
	createCredentialEndpoint = "/credential"
	verifyCredentialEndpoint = "/verify"
	createProfileEndpoint    = "/profile"
	getProfileEndpoint       = "/profile/{" + profilePathVariable
	profilePathVariable      = "profileID"

	successMsg = "success"

	// TODO create the profile and get the prefix of the ID from the profile issue-47
	id = "https://example.com/credentials/1872"
)

var errProfileNotFound = errors.New("specified profile ID does not exist")

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// New returns CreateCredential instance
func New(provider storage.Provider) (*Operation, error) {
	store, err := provider.OpenStore(credentialStore)
	if err != nil {
		return nil, err
	}

	profileStore := NewProfile(store)
	svc := &Operation{
		profileStore: profileStore,
	}
	svc.registerHandler()

	return svc, nil
}

// Operation defines handlers for Edge service
type Operation struct {
	handlers     []Handler
	profileStore *Profile
}

func (c *Operation) createCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	data := CreateCrendential{}
	err := json.NewDecoder(req.Body).Decode(&data)

	if err != nil {
		c.writeErrorResponse(rw, http.StatusBadRequest, "Failed to write response for invalid request received")

		return
	}

	validCredential, err := createCredential(&data)

	if err != nil {
		c.writeErrorResponse(rw, http.StatusBadRequest, "Failed to write response for create credential failure")

		return
	}

	rw.WriteHeader(http.StatusCreated)
	c.writeResponse(rw, validCredential)
}

func (c *Operation) verifyCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		c.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to read request body: %s", err.Error()))

		return
	}

	verified := true
	message := successMsg

	_, _, err = verifiable.NewCredential(body)
	if err != nil {
		verified = false
		message = err.Error()
	}

	response := &VerifyCredentialResponse{
		Verified: verified,
		Message:  message}

	rw.WriteHeader(http.StatusOK)
	c.writeResponse(rw, response)
}

func (c *Operation) createProfileHandler(rw http.ResponseWriter, req *http.Request) {
	data := ProfileRequest{}
	err := json.NewDecoder(req.Body).Decode(&data)

	if err != nil {
		c.writeErrorResponse(rw, http.StatusBadRequest, "Failed to write response for invalid request received")

		return
	}

	profileResponse, err := c.createProfile(&data)

	if err != nil {
		c.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	rw.WriteHeader(http.StatusCreated)
	c.writeResponse(rw, profileResponse)
}

func (c *Operation) getProfileHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	profileID := vars[profilePathVariable]

	profileResponseJSON, err := c.profileStore.GetProfile(profileID)
	if err != nil {
		if err == errProfileNotFound {
			c.writeErrorResponse(rw, http.StatusNotFound, "Failed to find the profile")

			return
		}

		c.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	c.writeResponse(rw, profileResponseJSON)
}

func createCredential(data *CreateCrendential) (*verifiable.Credential, error) {
	credential := &verifiable.Credential{}
	issueDate := time.Now().UTC()

	credential.Context = []string{credentialContext}
	credential.Subject = data.Subject
	credential.Types = data.Type
	credential.Issuer = data.Issuer
	credential.Issued = &issueDate
	// TODO to be replaced by getting profile ID issue-47
	credential.ID = id

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

func (c *Operation) createProfile(pr *ProfileRequest) (*ProfileResponse, error) {
	if pr.DID == "" {
		return nil, fmt.Errorf("missing DID information")
	}

	if pr.URI == "" {
		return nil, fmt.Errorf("missing URI information")
	}

	u, err := parseAndGetURI(pr.URI)
	if err != nil {
		return nil, err
	}

	issueDate := time.Now().UTC()
	profileResponse := &ProfileResponse{
		ID:        uuid.New().String(),
		URI:       u,
		IssueDate: &issueDate,
		DID:       pr.DID,
	}

	err = c.profileStore.SaveProfile(profileResponse)
	if err != nil {
		return nil, err
	}

	return profileResponse, nil
}
func parseAndGetURI(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("failed to parse the uri: %s", err.Error())
	}

	u.Path = path.Join(u.Path, uuid.New().String())

	return u.String(), nil
}

// writeResponse writes interface value to response
func (c *Operation) writeResponse(rw io.Writer, v interface{}) {
	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		log.Errorf("Unable to send error response, %s", err)
	}
}

func (c *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(createCredentialEndpoint, http.MethodPost, c.createCredentialHandler),
		support.NewHTTPHandler(createProfileEndpoint, http.MethodPost, c.createProfileHandler),
		support.NewHTTPHandler(getProfileEndpoint, http.MethodGet, c.getProfileHandler),
		support.NewHTTPHandler(verifyCredentialEndpoint, http.MethodPost, c.verifyCredentialHandler),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}
