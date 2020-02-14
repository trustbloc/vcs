/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	log "github.com/sirupsen/logrus"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"

	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
)

const (
	credentialStore = "credential"
	profile         = "/profile"

	// endpoints
	createCredentialEndpoint   = "/credential"
	verifyCredentialEndpoint   = "/verify"
	createProfileEndpoint      = profile
	getProfileEndpoint         = profile + "/{id}"
	storeCredentialEndpoint    = "/store"
	retrieveCredentialEndpoint = "/retrieve"

	successMsg        = "success"
	invalidUUIDErrMsg = "the UUID in the VC ID was not in a valid format"
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
func New(provider storage.Provider, client Client, kms legacykms.KMS, vdri vdriapi.Registry) (*Operation, error) {
	store, err := provider.OpenStore(credentialStore)
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		profileStore: vcprofile.New(store),
		client:       client,
		vdri:         vdri,
		crypto:       crypto.New(kms, verifiable.NewDIDKeyResolver(vdri)),
	}

	svc.registerHandler()

	return svc, nil
}

// Operation defines handlers for Edge service
type Operation struct {
	handlers     []Handler
	profileStore *vcprofile.Profile
	client       Client
	vdri         vdriapi.Registry
	crypto       *crypto.Crypto
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

	signedVC, err := o.crypto.SignCredential(profile, validCredential)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential: %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusCreated)
	o.writeResponse(rw, signedVC)
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

	_, err = o.parseAndVerifyVC(body)
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

	vc, err := o.parseAndVerifyVC([]byte(data.Credential))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("unable to unmarshal the VC: %s", err.Error()))
		return
	}

	if err = validateRequest(data.Profile, vc.ID); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	doc := operation.StructuredDocument{}
	doc.Content = make(map[string]interface{})
	doc.Content["message"] = data.Credential

	// We need an EDV-compliant ID. The UUID that's in the VC is a good fit, since it's 128 bits long already.
	// Let's convert it to base58 and use it as the StructuredDocument ID.
	edvDocID, err := convertVCIDToEDVCompatibleFormat(vc.ID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	doc.ID = edvDocID

	_, err = o.client.CreateDocument(data.Profile, &doc)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}
}

// This function expects the vcID that's passed in to be a URL with a "/" and then a UUID concatenated to the end.
func convertVCIDToEDVCompatibleFormat(vcID string) (string, error) {
	vcIDParts := strings.Split(vcID, "/")

	uuidFromVCID := vcIDParts[len(vcIDParts)-1]

	parsedUUID, err := uuid.Parse(uuidFromVCID)
	if err != nil {
		return "", fmt.Errorf("%s: %s", invalidUUIDErrMsg, err.Error())
	}

	base58EncodedUUID := base58.Encode(parsedUUID[:])

	return base58EncodedUUID, nil
}

func (o *Operation) retrieveVCHandler(rw http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	profile := req.URL.Query().Get("profile")

	if err := validateRequest(profile, id); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	edvDocID, err := convertVCIDToEDVCompatibleFormat(id)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	documentBytes, err := o.client.ReadDocument(profile, edvDocID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	document := operation.StructuredDocument{}

	err = json.Unmarshal(documentBytes, &document)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("structured document unmarshalling failed: %s", err.Error()))

		return
	}

	responseMsg, err := json.Marshal(document.Content["message"])
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("structured document content marshalling failed: %s", err.Error()))

		return
	}

	_, err = rw.Write(responseMsg)
	if err != nil {
		log.Errorf("Failed to write response for document retrieval success: %s",
			err.Error())

		return
	}
}

func createCredential(profile *vcprofile.DataProfile, data *CreateCredentialRequest) (*verifiable.Credential, error) {
	credential := &verifiable.Credential{}

	issueDate := time.Now().UTC()

	credential.Context = data.Context
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

func (o *Operation) createProfile(pr *ProfileRequest) (*vcprofile.DataProfile, error) {
	if err := validateProfileRequest(pr); err != nil {
		return nil, err
	}

	// TODO how to figure out create method ?
	didDoc, err := o.vdri.Create("sidetree", vdriapi.WithRequestBuilder(buildSideTreeRequest))
	if err != nil {
		return nil, fmt.Errorf("failed to create did doc: %v", err)
	}

	created := time.Now().UTC()
	profileResponse := &vcprofile.DataProfile{
		Name:          pr.Name,
		URI:           pr.URI,
		Created:       &created,
		DID:           didDoc.ID,
		SignatureType: pr.SignatureType,
		Creator:       didDoc.ID + didDoc.PublicKey[0].ID,
	}

	err = o.profileStore.SaveProfile(profileResponse)
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

// buildSideTreeRequest request builder for sidetree public DID creation
func buildSideTreeRequest(docBytes []byte) (io.Reader, error) {
	request := &model.Request{
		Header: &model.Header{
			Operation: model.OperationTypeCreate, Alg: "", Kid: ""},
		Payload:   base64.URLEncoding.EncodeToString(docBytes),
		Signature: ""}

	b, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(b), nil
}

func validateProfileRequest(pr *ProfileRequest) error {
	if pr.Name == "" {
		return fmt.Errorf("missing profile name")
	}

	if pr.URI == "" {
		return fmt.Errorf("missing URI information")
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

func (o *Operation) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	vc, _, err := verifiable.NewCredential(vcBytes,
		verifiable.WithEmbeddedSignatureSuites(ed25519signature2018.New()),
		verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(o.vdri).PublicKeyFetcher()))
	if err != nil {
		return nil, err
	}

	return vc, nil
}
