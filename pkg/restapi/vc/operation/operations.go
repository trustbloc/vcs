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
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
)

const (
	credentialStore   = "credential"
	profile           = "/profile"
	credentialContext = "https://www.w3.org/2018/credentials/v1"

	// endpoints
	createCredentialEndpoint   = "/credential"
	verifyCredentialEndpoint   = "/verify"
	createProfileEndpoint      = profile
	getProfileEndpoint         = profile + "/{id}"
	storeCredentialEndpoint    = "/store"
	retrieveCredentialEndpoint = "/retrieve"

	successMsg = "success"
)

var errProfileNotFound = errors.New("specified profile ID does not exist")

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Client interface to interact with edv client
type Client interface {
	CreateDataVault(config *operation.DataVaultConfiguration) (string, error)
	CreateDocument(vaultID string, document *operation.StructuredDocument) (string, error)
	ReadDocument(vaultID, docID string) ([]byte, error)
}

// New returns CreateCredential instance
func New(provider storage.Provider, client Client) (*Operation, error) {
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
		client: client,
	}

	svc.registerHandler()

	return svc, nil
}

// Operation defines handlers for Edge service
type Operation struct {
	handlers     []Handler
	profileStore *Profile
	keySet       *keySet
	client       Client
}

// KeySet will be replaced with KMS/profile configuration
type keySet struct {
	private []byte
	public  []byte
}

func (o *Operation) createCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	data := CreateCredentialRequest{}
	err := json.NewDecoder(req.Body).Decode(&data)

	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, "Failed to write response for invalid request received")

		return
	}

	profile, err := o.profileStore.GetProfile(data.Profile)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to read profile: %s", err.Error()))

		return
	}

	validCredential, err := createCredential(profile, &data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to create credential: %s", err.Error()))

		return
	}

	signedVC, err := o.signCredential(profile, validCredential)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential: %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusCreated)
	o.writeResponse(rw, signedVC)
}

func (o *Operation) signCredential(profile *ProfileResponse, vc *verifiable.Credential) (*verifiable.Credential, error) { // nolint:lll
	signingCtx := &verifiable.LinkedDataProofContext{
		Creator:       profile.Creator,
		SignatureType: profile.SignatureType,
		Suite:         ed25519signature2018.New(),
		PrivateKey:    o.keySet.private,
	}

	err := vc.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (o *Operation) verifyCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to read request body: %s", err.Error()))

		return
	}

	verified := true
	message := successMsg

	// Q: should signature suite this be passed in or handled (loaded automatically) by verifiable package
	// based on signature type in proof
	// Q: we should have default implementation for key fetcher in verifiable package as well
	_, _, err = verifiable.NewCredential(body, verifiable.WithEmbeddedSignatureSuites(ed25519signature2018.New()),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(o.keySet.public)))
	if err != nil {
		verified = false
		message = err.Error()
	}

	response := &VerifyCredentialResponse{
		Verified: verified,
		Message:  message}

	rw.WriteHeader(http.StatusOK)
	o.writeResponse(rw, response)
}

func (o *Operation) createProfileHandler(rw http.ResponseWriter, req *http.Request) {
	data := ProfileRequest{}
	err := json.NewDecoder(req.Body).Decode(&data)

	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, "Failed to write response for invalid request received")

		return
	}

	profileResponse, err := o.createProfile(&data)

	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	rw.WriteHeader(http.StatusCreated)
	o.writeResponse(rw, profileResponse)
}

func (o *Operation) getProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)["id"]

	profileResponseJSON, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		if err == errProfileNotFound {
			o.writeErrorResponse(rw, http.StatusNotFound, "Failed to find the profile")

			return
		}

		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	o.writeResponse(rw, profileResponseJSON)
}

func (o *Operation) storeVCHandler(rw http.ResponseWriter, req *http.Request) {
	data := &StoreVCRequest{}
	err := json.NewDecoder(req.Body).Decode(&data)

	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, "invalid request received")

		return
	}

	if err = validateRequest(data.Profile, data.Credential.ID); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	doc := operation.StructuredDocument{}
	doc.Content = make(map[string]interface{})
	doc.Content["message"] = data.Credential
	doc.ID = data.Credential.ID

	_, err = o.client.CreateDocument(data.Profile, &doc)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}
}

func (o *Operation) retrieveVCHandler(rw http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	profile := req.URL.Query().Get("profile")

	if err := validateRequest(profile, id); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	documentBytes, err := o.client.ReadDocument(profile, id)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	document := operation.StructuredDocument{}

	err = json.Unmarshal(documentBytes, &document)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("structured document unmarshalling failed: %s", err.Error()))
	}

	responseMsg, err := json.Marshal(document.Content["message"])
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("structured document content marshalling failed: %s", err.Error()))
	}

	_, err = rw.Write(responseMsg)
	if err != nil {
		log.Errorf("Failed to write response for document retrieval success: %s",
			err.Error())
	}
}

func createCredential(profile *ProfileResponse, data *CreateCredentialRequest) (*verifiable.Credential, error) {
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

func (o *Operation) createProfile(pr *ProfileRequest) (*ProfileResponse, error) {
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

	err := o.profileStore.SaveProfile(profileResponse)
	if err != nil {
		return nil, err
	}

	// create the vault associated with the profile
	_, err = o.client.CreateDataVault(&operation.DataVaultConfiguration{ReferenceID: pr.Name})
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

func validateRequest(profileName, vcID string) error {
	if profileName == "" {
		return fmt.Errorf("missing profile name")
	}

	if vcID == "" {
		return fmt.Errorf("missing verifiable credential ID")
	}

	return nil
}

// writeResponse writes interface value to response
func (o *Operation) writeResponse(rw io.Writer, v interface{}) {
	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		log.Errorf("Unable to send error response, %s", err)
	}
}

func (o *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (o *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	o.handlers = []Handler{
		support.NewHTTPHandler(createCredentialEndpoint, http.MethodPost, o.createCredentialHandler),
		support.NewHTTPHandler(createProfileEndpoint, http.MethodPost, o.createProfileHandler),
		support.NewHTTPHandler(getProfileEndpoint, http.MethodGet, o.getProfileHandler),
		support.NewHTTPHandler(storeCredentialEndpoint, http.MethodPost, o.storeVCHandler),
		support.NewHTTPHandler(verifyCredentialEndpoint, http.MethodPost, o.verifyCredentialHandler),
		support.NewHTTPHandler(retrieveCredentialEndpoint, http.MethodGet, o.retrieveVCHandler),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []Handler {
	return o.handlers
}
