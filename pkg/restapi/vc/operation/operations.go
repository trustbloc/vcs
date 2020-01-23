/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
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

	// TODO: replace by KMS
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		profileStore: NewProfile(store),
		// TODO: replace private key by signer, public key by resolver
		keySet: &keySet{private: privKey, public: pubKey},
	}

	// TODO: Remove default profile when bdd test is done
	err = svc.profileStore.SaveProfile(&ProfileResponse{
		Name:          "issuer",
		DID:           "did:method:abc",
		URI:           "https://issuer.com/credentials",
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:method:abc#key1",
	})
	if err != nil {
		return nil, err
	}

	svc.registerHandler()

	return svc, nil
}

// Operation defines handlers for Edge service
type Operation struct {
	handlers     []Handler
	profileStore *Profile
	keySet       *keySet
}

// KeySet will be replaced with KMS/profile configuration
type keySet struct {
	private []byte
	public  []byte
}

func (c *Operation) createCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	data := CreateCredential{}
	err := json.NewDecoder(req.Body).Decode(&data)

	if err != nil {
		c.writeErrorResponse(rw, http.StatusBadRequest, "Failed to write response for invalid request received")

		return
	}

	profile, err := c.profileStore.GetProfile(data.Profile)
	if err != nil {
		c.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to read profile: %s", err.Error()))

		return
	}

	validCredential, err := createCredential(profile, &data)
	if err != nil {
		c.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to create credential: %s", err.Error()))

		return
	}

	signedVC, err := c.signCredential(profile, validCredential)
	if err != nil {
		c.writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential: %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusCreated)
	c.writeResponse(rw, signedVC)
}

func (c *Operation) signCredential(profile *ProfileResponse, vc *verifiable.Credential) (*verifiable.Credential, error) { // nolint:lll
	signingCtx := &verifiable.LinkedDataProofContext{
		Creator:       profile.Creator,
		SignatureType: profile.SignatureType,
		Suite:         ed25519signature2018.New(),
		PrivateKey:    c.keySet.private,
	}

	err := vc.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (c *Operation) verifyCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		c.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to read request body: %s", err.Error()))

		return
	}

	verified := true
	message := successMsg

	// Q: should signature suite this be passed in or handled (loaded automatically) by verifiable package
	// based on signature type in proof
	// Q: we should have default implementation for key fetcher in verifiable package as well
	_, _, err = verifiable.NewCredential(body, verifiable.WithEmbeddedSignatureSuites(ed25519signature2018.New()),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(c.keySet.public)))
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

func createCredential(profile *ProfileResponse, data *CreateCredential) (*verifiable.Credential, error) {
	credential := &verifiable.Credential{}
	issueDate := time.Now().UTC()

	credential.Context = []string{credentialContext}
	credential.Subject = data.Subject
	credential.Types = data.Type
	credential.Issuer = verifiable.Issuer{
		ID:   profile.DID,
		Name: profile.Name,
	}
	credential.Issued = &issueDate
	credential.ID = profile.URI + "/" + uuid.New().String()

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
	if err := validateProfileRequest(pr); err != nil {
		return nil, err
	}

	created := time.Now().UTC()
	profileResponse := &ProfileResponse{
		Name:          pr.Name,
		URI:           pr.URI,
		Created:       &created,
		DID:           pr.DID,
		SignatureType: pr.SignatureType,
		Creator:       pr.Creator,
	}

	err := c.profileStore.SaveProfile(profileResponse)
	if err != nil {
		return nil, err
	}

	return profileResponse, nil
}

func validateProfileRequest(pr *ProfileRequest) error {
	if pr.Name == "" {
		return fmt.Errorf("missing profile name")
	}

	if pr.DID == "" {
		return fmt.Errorf("missing DID information")
	}

	if pr.URI == "" {
		return fmt.Errorf("missing URI information")
	}

	if pr.Creator == "" {
		return fmt.Errorf("missing creator")
	}

	if pr.SignatureType == "" {
		return fmt.Errorf("missing signature type")
	}

	_, err := url.Parse(pr.URI)
	if err != nil {
		return fmt.Errorf("invalid uri: %s", err.Error())
	}

	return nil
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
