/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/rand"
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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	log "github.com/sirupsen/logrus"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
	didclient "github.com/trustbloc/trustbloc-did-method/pkg/did"

	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
)

const (
	credentialStoreName = "credential"
	profile             = "/profile"

	// endpoints
	createCredentialEndpoint       = "/credential"
	verifyCredentialEndpoint       = "/verify"
	updateCredentialStatusEndpoint = "/updateStatus"
	createProfileEndpoint          = profile
	getProfileEndpoint             = profile + "/{id}"
	storeCredentialEndpoint        = "/store"
	retrieveCredentialEndpoint     = "/retrieve"
	verifyPresentationEndpoint     = "/verifyPresentation"

	successMsg = "success"
	cslSize    = 50

	// IDMappingStoreName is the name given to the store that contains the VC ID -> EDV document ID mapping.
	IDMappingStoreName = "id-mapping"

	invalidRequestErrMsg = "Invalid request"
)

var errProfileNotFound = errors.New("specified profile ID does not exist")

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type vcStatusManager interface {
	CreateStatusID() (*verifiable.TypedID, error)
	UpdateVCStatus(v *verifiable.Credential, profile *vcprofile.DataProfile, status, statusReason string) error
	GetCSL(id string) (*cslstatus.CSL, error)
}

// EDVClient interface to interact with edv client
type EDVClient interface {
	CreateDataVault(config *operation.DataVaultConfiguration) (string, error)
	CreateDocument(vaultID string, document *operation.EncryptedDocument) (string, error)
	ReadDocument(vaultID, docID string) (*operation.EncryptedDocument, error)
}

type didBlocClient interface {
	CreateDID(domain string) (*did.Doc, error)
}

type kmsProvider struct {
	kms legacykms.KeyManager
}

func (p kmsProvider) LegacyKMS() legacykms.KeyManager {
	return p.kms
}

// New returns CreateCredential instance
func New(config *Config) (*Operation, error) {
	err := config.StoreProvider.CreateStore(credentialStoreName)
	if err != nil {
		if err != storage.ErrDuplicateStore {
			return nil, err
		}
	}

	store, err := config.StoreProvider.OpenStore(credentialStoreName)
	if err != nil {
		return nil, err
	}

	//TODO: Should this be opened in the same store? https://github.com/trustbloc/edge-service/issues/112
	err = config.StoreProvider.CreateStore(IDMappingStoreName)
	if err != nil {
		if err != storage.ErrDuplicateStore {
			return nil, err
		}
	}

	idMappingStore, err := config.StoreProvider.OpenStore(IDMappingStoreName)
	if err != nil {
		return nil, err
	}

	c := crypto.New(config.KMS, verifiable.NewDIDKeyResolver(config.VDRI))

	vcStatusManager, err := cslstatus.New(config.StoreProvider, config.HostURL, cslSize, c)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new csl status: %w", err)
	}

	kmsProv := kmsProvider{
		kms: config.KMS,
	}

	packer := authcrypt.New(kmsProv)

	_, senderKey, err := config.KMS.CreateKeySet()
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		profileStore:    vcprofile.New(store),
		edvClient:       config.EDVClient,
		vdri:            config.VDRI,
		crypto:          c,
		packer:          packer,
		senderKey:       senderKey,
		vcStatusManager: vcStatusManager,
		didBlocClient:   didclient.New(config.KMS),
		domain:          config.Domain,
		idMappingStore:  idMappingStore,
	}

	return svc, nil
}

// Config defines configuration for vcs operations
type Config struct {
	StoreProvider storage.Provider
	EDVClient     EDVClient
	KMS           legacykms.KMS
	VDRI          vdriapi.Registry
	HostURL       string
	Domain        string
	Mode          string
}

// Operation defines handlers for Edge service
type Operation struct {
	profileStore    *vcprofile.Profile
	edvClient       EDVClient
	vdri            vdriapi.Registry
	crypto          *crypto.Crypto
	packer          *authcrypt.Packer
	senderKey       string
	vcStatusManager vcStatusManager
	didBlocClient   didBlocClient
	domain          string
	idMappingStore  storage.Store
}

func (o *Operation) createCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	data := CreateCredentialRequest{}

	err := json.NewDecoder(req.Body).Decode(&data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	profile, err := o.profileStore.GetProfile(data.Profile)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to read profile: %s", err.Error()))

		return
	}

	validCredential, err := o.createCredential(profile, &data)
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

	// verify vc
	vc, err := o.parseAndVerifyVC(body)
	if err != nil {
		response := &VerifyCredentialResponse{
			Verified: false,
			Message:  err.Error()}

		rw.WriteHeader(http.StatusOK)
		o.writeResponse(rw, response)

		return
	}

	// vc is verified
	// now to check vc status
	resp, err := o.checkVCStatus(vc.Status.ID, vc.ID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			err.Error())

		return
	}

	rw.WriteHeader(http.StatusOK)
	o.writeResponse(rw, resp)
}

func (o *Operation) checkVCStatus(vclID, vcID string) (*VerifyCredentialResponse, error) {
	vcResp := &VerifyCredentialResponse{
		Verified: false}

	csl, err := o.vcStatusManager.GetCSL(vclID)
	if err != nil {
		vcResp.Message = fmt.Sprintf("failed to get credential status list: %s", err.Error())
		return vcResp, nil
	}

	for _, vcStatus := range csl.VC {
		if !strings.Contains(vcStatus, vcID) {
			continue
		}

		statusVc, err := o.parseAndVerifyVC([]byte(vcStatus))
		if err != nil {
			return nil, fmt.Errorf("failed to parse and verify status vc: %s", err.Error())
		}

		subjectBytes, err := json.Marshal(statusVc.Subject)
		if err != nil {
			return nil, fmt.Errorf(fmt.Sprintf("failed to marshal status vc subject: %s", err.Error()))
		}

		vcResp.Message = string(subjectBytes)

		return vcResp, nil
	}

	vcResp.Verified = true
	vcResp.Message = successMsg

	return vcResp, nil
}

func (o *Operation) updateCredentialStatusHandler(rw http.ResponseWriter, req *http.Request) {
	data := UpdateCredentialStatusRequest{}
	err := json.NewDecoder(req.Body).Decode(&data)

	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request received: %s", err.Error()))
		return
	}

	vc, err := o.parseAndVerifyVC([]byte(data.Credential))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("unable to unmarshal the VC: %s", err.Error()))
		return
	}

	// get profile
	profile, err := o.profileStore.GetProfile(vc.Issuer.Name)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to get profile: %s", err.Error()))
		return
	}

	if err := o.vcStatusManager.UpdateVCStatus(vc, profile, data.Status, data.StatusReason); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to update vc status: %s", err.Error()))
		return
	}

	rw.WriteHeader(http.StatusOK)
}

func (o *Operation) createProfileHandler(rw http.ResponseWriter, req *http.Request) {
	data := ProfileRequest{}

	err := json.NewDecoder(req.Body).Decode(&data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

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
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

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

	o.storeVC(data, vc, rw)
}

func (o *Operation) storeVC(data *StoreVCRequest, vc *verifiable.Credential, rw http.ResponseWriter) {
	doc, err := o.buildStructuredDoc(data, vc)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	marshalledStructuredDoc, err := json.Marshal(doc)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	// We have no recipients, so we pass in the sender key as the recipient key as well
	encryptedStructuredDoc, err := o.packer.Pack(marshalledStructuredDoc,
		base58.Decode(o.senderKey), [][]byte{base58.Decode(o.senderKey)})
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	encryptedDocument := operation.EncryptedDocument{
		ID:       doc.ID,
		Sequence: 0,
		JWE:      encryptedStructuredDoc,
	}

	_, err = o.edvClient.CreateDocument(data.Profile, &encryptedDocument)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	err = o.idMappingStore.Put(vc.ID, []byte(doc.ID))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}
}

func (o *Operation) buildStructuredDoc(data *StoreVCRequest,
	vc *verifiable.Credential) (*operation.StructuredDocument, error) {
	var edvDocID string

	idFromMapping, err := o.idMappingStore.Get(vc.ID)
	switch err {
	case storage.ErrValueNotFound:
		edvDocID, err = generateEDVCompatibleID()
		if err != nil {
			return nil, err
		}
	case nil:
		edvDocID = string(idFromMapping)
	default:
		return nil, err
	}

	doc := operation.StructuredDocument{}
	doc.ID = edvDocID
	doc.Content = make(map[string]interface{})

	credentialBytes := []byte(data.Credential)

	var credentialJSONRawMessage json.RawMessage = credentialBytes

	doc.Content["message"] = credentialJSONRawMessage

	return &doc, nil
}

func generateEDVCompatibleID() (string, error) {
	randomBytes := make([]byte, 16)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	base58EncodedUUID := base58.Encode(randomBytes)

	return base58EncodedUUID, nil
}

func (o *Operation) retrieveVCHandler(rw http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	profile := req.URL.Query().Get("profile")

	if err := validateRequest(profile, id); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	edvDocID, err := o.idMappingStore.Get(id)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	document, err := o.edvClient.ReadDocument(profile, string(edvDocID))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	decryptedEnvelope, err := o.packer.Unpack(document.JWE)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("decrypted envelope unpacking failed: %s", err.Error()))

		return
	}

	decryptedDoc := operation.StructuredDocument{}

	err = json.Unmarshal(decryptedEnvelope.Message, &decryptedDoc)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("decrypted structured document unmarshalling failed: %s", err.Error()))

		return
	}

	responseMsg, err := json.Marshal(decryptedDoc.Content["message"])
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

func (o *Operation) verifyVPHandler(rw http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to read request body: %s", err.Error()))

		return
	}
	// verify vp
	_, err = o.parseAndVerifyVP(body)
	if err != nil {
		response := &VerifyCredentialResponse{
			Verified: false,
			Message:  err.Error()}

		rw.WriteHeader(http.StatusOK)
		o.writeResponse(rw, response)

		return
	}

	resp := &VerifyCredentialResponse{
		Verified: true,
		Message:  successMsg,
	}

	rw.WriteHeader(http.StatusOK)
	o.writeResponse(rw, resp)
}

func (o *Operation) createCredential(profile *vcprofile.DataProfile,
	data *CreateCredentialRequest) (*verifiable.Credential, error) {
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

	var err error

	credential.Status, err = o.vcStatusManager.CreateStatusID()
	if err != nil {
		return nil, fmt.Errorf("failed to create status id for vc: %w", err)
	}

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

	var didDoc *did.Doc

	var err error

	if pr.DID == "" {
		didDoc, err = o.didBlocClient.CreateDID(o.domain)
		if err != nil {
			return nil, fmt.Errorf("failed to create did doc: %v", err)
		}
	} else {
		didDoc, err = o.vdri.Resolve(pr.DID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve did: %v", err)
		}
	}

	var publicKeyID string

	switch {
	case len(didDoc.PublicKey) > 0:
		publicKeyID = didDoc.PublicKey[0].ID
	case len(didDoc.Authentication) > 0:
		publicKeyID = didDoc.Authentication[0].PublicKey.ID
	default:
		return nil, fmt.Errorf("can't find public key in DID")
	}

	created := time.Now().UTC()
	profileResponse := &vcprofile.DataProfile{
		Name:                    pr.Name,
		URI:                     pr.URI,
		Created:                 &created,
		DID:                     didDoc.ID,
		SignatureType:           pr.SignatureType,
		SignatureRepresentation: pr.SignatureRepresentation,
		Creator:                 publicKeyID,
		DIDPrivateKey:           pr.DIDPrivateKey,
	}

	err = o.profileStore.SaveProfile(profileResponse)
	if err != nil {
		return nil, err
	}

	// create the vault associated with the profile
	_, err = o.edvClient.CreateDataVault(&operation.DataVaultConfiguration{ReferenceID: pr.Name})
	if err != nil {
		return nil, err
	}

	return profileResponse, nil
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

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers(mode string) ([]Handler, error) {
	switch mode {
	case "verifier":
		return []Handler{
			support.NewHTTPHandler(verifyCredentialEndpoint, http.MethodPost, o.verifyCredentialHandler),
		}, nil
	case "issuer":
		return []Handler{
			support.NewHTTPHandler(createCredentialEndpoint, http.MethodPost, o.createCredentialHandler),
			support.NewHTTPHandler(createProfileEndpoint, http.MethodPost, o.createProfileHandler),
			support.NewHTTPHandler(getProfileEndpoint, http.MethodGet, o.getProfileHandler),
			support.NewHTTPHandler(storeCredentialEndpoint, http.MethodPost, o.storeVCHandler),
			support.NewHTTPHandler(verifyCredentialEndpoint, http.MethodPost, o.verifyCredentialHandler),
			support.NewHTTPHandler(updateCredentialStatusEndpoint, http.MethodPost, o.updateCredentialStatusHandler),
			support.NewHTTPHandler(retrieveCredentialEndpoint, http.MethodGet, o.retrieveVCHandler),
			support.NewHTTPHandler(verifyPresentationEndpoint, http.MethodPost, o.verifyVPHandler),
		}, nil
	default:
		return nil, fmt.Errorf("invalid operation mode: %s", mode)
	}
}

func (o *Operation) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	vc, _, err := verifiable.NewCredential(
		vcBytes,
		verifiable.WithEmbeddedSignatureSuites(ed25519signature2018.New()),
		verifiable.WithPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(o.vdri).PublicKeyFetcher(),
		),
	)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (o *Operation) parseAndVerifyVP(vpBytes []byte) (*verifiable.Presentation, error) {
	vp, err := verifiable.NewPresentation(
		vpBytes,
		verifiable.WithPresEmbeddedSignatureSuites(ed25519signature2018.New()),
		verifiable.WithPresPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(o.vdri).PublicKeyFetcher(),
		),
	)
	if err != nil {
		return nil, err
	}
	// vp is verified

	// verify if the credentials in vp are valid
	for _, cred := range vp.Credentials() {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}
		// verify if the credential in vp is valid
		_, err = o.parseAndVerifyVC(vcBytes)
		if err != nil {
			return nil, err
		}
	}

	return vp, nil
}
