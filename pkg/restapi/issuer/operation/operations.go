/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/tink/go/keyset"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/utils/retry"
	"github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"

	zcapsvc "github.com/trustbloc/edge-service/pkg/auth/zcapld"
	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/internal/cryptosetup"
	commondid "github.com/trustbloc/edge-service/pkg/restapi/internal/common/did"
	commhttp "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"
	"github.com/trustbloc/edge-service/pkg/restapi/internal/common/vcutil"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

const (
	logModuleName      = "edge-service-issuer-restapi"
	profileIDPathParam = "profileID"

	// issuer endpoints
	createProfileEndpoint          = "/profile"
	getProfileEndpoint             = createProfileEndpoint + "/{id}"
	deleteProfileEndpoint          = createProfileEndpoint + "/{id}"
	storeCredentialEndpoint        = "/store"
	retrieveCredentialEndpoint     = "/retrieve"
	credentialStatus               = "/status"
	updateCredentialStatusEndpoint = "/updateStatus"
	credentialStatusEndpoint       = credentialStatus + "/{id}"
	credentialsBasePath            = "/" + "{" + profileIDPathParam + "}" + "/credentials"
	issueCredentialPath            = credentialsBasePath + "/issueCredential"
	composeAndIssueCredentialPath  = credentialsBasePath + "/composeAndIssueCredential"
	kmsBasePath                    = "/kms"
	generateKeypairPath            = kmsBasePath + "/generatekeypair"

	cslSize = 1000

	invalidRequestErrMsg = "Invalid request"

	// supported proof purpose
	assertionMethod      = "assertionMethod"
	authentication       = "authentication"
	capabilityDelegation = "capabilityDelegation"
	capabilityInvocation = "capabilityInvocation"

	splitAssertionMethodLength = 2
)

var logger = log.New("edge-service-issuer-restapi")

var errProfileNotFound = errors.New("specified profile ID does not exist")
var errNoDocsMatchQuery = errors.New("no documents match the given query")

var errMultipleInconsistentVCsFoundForOneID = errors.New("multiple VCs with " +
	"differing contents were found matching the given ID. This indicates inconsistency in " +
	"the VC database. To solve this, delete the extra VCs and leave only one")

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type vcStatusManager interface {
	CreateStatusID(profile *vcprofile.DataProfile) (*verifiable.TypedID, error)
	RevokeVC(v *verifiable.Credential, profile *vcprofile.DataProfile) error
	GetRevocationListVC(id string) ([]byte, error)
}

// EDVClient interface to interact with edv client
type EDVClient interface {
	CreateDataVault(config *models.DataVaultConfiguration, opts ...client.ReqOption) (string, []byte, error)
	CreateDocument(vaultID string, document *models.EncryptedDocument, opts ...client.ReqOption) (string, error)
	ReadDocument(vaultID, docID string, opts ...client.ReqOption) (*models.EncryptedDocument, error)
	QueryVault(vaultID, name, value string, opts ...client.ReqOption) ([]string, error)
}

type authService interface {
	CreateDIDKey() (string, error)
	SignHeader(req *http.Request, capabilityBytes []byte, verificationMethod string) (*http.Header, error)
}

type keyManager interface {
	kms.KeyManager
}

type commonDID interface {
	CreateDID(keyType, signatureType, did, privateKey, keyID, purpose string,
		registrar model.UNIRegistrar) (string, string, error)
}

// New returns CreateCredential instance
func New(config *Config) (*Operation, error) {
	c := crypto.New(config.KeyManager, config.Crypto, config.VDRI)

	vcStatusManager, err := cslstatus.New(config.StoreProvider, config.HostURL+credentialStatus, cslSize, c)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new csl status: %w", err)
	}

	jweEncrypter, jweDecrypter, err := cryptosetup.PrepareJWECrypto(config.KeyManager, config.StoreProvider,
		config.Crypto, jose.A256GCM, kms.NISTP256ECDHKWType)
	if err != nil {
		return nil, err
	}

	kh, vcIDIndexNameMACEncoded, err :=
		cryptosetup.PrepareMACCrypto(config.KeyManager, config.StoreProvider, config.Crypto, kms.HMACSHA256Tag256Type)
	if err != nil {
		return nil, err
	}

	p, err := vcprofile.New(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		authService:          zcapsvc.New(config.KeyManager, config.Crypto),
		profileStore:         p,
		edvClient:            config.EDVClient,
		kms:                  config.KeyManager,
		vdr:                  config.VDRI,
		crypto:               c,
		jweEncrypter:         jweEncrypter,
		jweDecrypter:         jweDecrypter,
		vcStatusManager:      vcStatusManager,
		domain:               config.Domain,
		HostURL:              config.HostURL,
		macKeyHandle:         kh,
		macCrypto:            config.Crypto,
		vcIDIndexNameEncoded: vcIDIndexNameMACEncoded,
		commonDID: commondid.New(&commondid.Config{VDRI: config.VDRI, KeyManager: config.KeyManager,
			Domain: config.Domain, TLSConfig: config.TLSConfig}),
		retryParameters: config.RetryParameters,
	}

	return svc, nil
}

// Config defines configuration for vcs operations
type Config struct {
	StoreProvider      ariesstorage.Provider
	KMSSecretsProvider ariesstorage.Provider
	EDVClient          EDVClient
	KeyManager         keyManager
	VDRI               vdrapi.Registry
	HostURL            string
	Domain             string
	TLSConfig          *tls.Config
	Crypto             ariescrypto.Crypto
	RetryParameters    *retry.Params
}

// Operation defines handlers for Edge service
type Operation struct {
	profileStore         *vcprofile.Profile
	edvClient            EDVClient
	kms                  keyManager
	vdr                  vdrapi.Registry
	crypto               *crypto.Crypto
	jweEncrypter         jose.Encrypter
	jweDecrypter         jose.Decrypter
	vcStatusManager      vcStatusManager
	domain               string
	HostURL              string
	macKeyHandle         *keyset.Handle
	macCrypto            ariescrypto.Crypto
	vcIDIndexNameEncoded string
	commonDID            commonDID
	retryParameters      *retry.Params
	authService          authService
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		// issuer profile
		support.NewHTTPHandler(createProfileEndpoint, http.MethodPost, o.createIssuerProfileHandler),
		support.NewHTTPHandler(getProfileEndpoint, http.MethodGet, o.getIssuerProfileHandler),
		support.NewHTTPHandler(deleteProfileEndpoint, http.MethodDelete, o.deleteIssuerProfileHandler),

		// verifiable credential store
		support.NewHTTPHandler(storeCredentialEndpoint, http.MethodPost, o.storeCredentialHandler),
		support.NewHTTPHandler(retrieveCredentialEndpoint, http.MethodGet, o.retrieveCredentialHandler),

		// verifiable credential status
		support.NewHTTPHandler(updateCredentialStatusEndpoint, http.MethodPost, o.updateCredentialStatusHandler),
		support.NewHTTPHandler(credentialStatusEndpoint, http.MethodGet, o.retrieveCredentialStatus),

		// issuer apis
		support.NewHTTPHandler(generateKeypairPath, http.MethodGet, o.generateKeypairHandler),
		support.NewHTTPHandler(issueCredentialPath, http.MethodPost, o.issueCredentialHandler),
		support.NewHTTPHandler(composeAndIssueCredentialPath, http.MethodPost, o.composeAndIssueCredentialHandler),
	}
}

// RetrieveCredentialStatus swagger:route GET /status/{id} issuer retrieveCredentialStatusReq
//
// Retrieves the credential status.
//
// Responses:
//    default: genericError
//        200: retrieveCredentialStatusResp
func (o *Operation) retrieveCredentialStatus(rw http.ResponseWriter, req *http.Request) {
	revocationListVCBytes, err := o.vcStatusManager.GetRevocationListVC(o.HostURL + req.RequestURI)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to get credential status list: %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusOK)

	if _, err = rw.Write(revocationListVCBytes); err != nil {
		logger.Errorf("Unable to send response, %s", err)
	}
}

// UpdateCredentialStatus swagger:route POST /updateStatus issuer updateCredentialStatusReq
//
// Updates credential status.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) updateCredentialStatusHandler(rw http.ResponseWriter, req *http.Request) {
	data := UpdateCredentialStatusRequest{}
	err := json.NewDecoder(req.Body).Decode(&data)

	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request received: %s", err.Error()))
		return
	}

	for _, cred := range data.Credentials {
		vc, err := o.parseAndVerifyVC(cred)
		if err != nil {
			commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
				fmt.Sprintf("unable to unmarshal the VC: %s", err.Error()))
			return
		}

		// get profile
		profile, err := o.profileStore.GetProfile(vc.Issuer.CustomFields["name"].(string))
		if err != nil {
			commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
				fmt.Sprintf("failed to get profile: %s", err.Error()))
			return
		}

		if profile.DisableVCStatus {
			commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
				fmt.Sprintf("vc status is disabled for profile %s", profile.Name))
			return
		}

		if err := o.vcStatusManager.RevokeVC(vc, profile.DataProfile); err != nil {
			commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
				fmt.Sprintf("failed to update vc status: %s", err.Error()))
			return
		}
	}

	rw.WriteHeader(http.StatusOK)
}

// CreateIssuerProfile swagger:route POST /profile issuer issuerProfileReq
//
// Creates issuer profile.
//
// Responses:
//    default: genericError
//        201: issuerProfileRes
func (o *Operation) createIssuerProfileHandler(rw http.ResponseWriter, req *http.Request) {
	data := ProfileRequest{}

	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	if err := validateProfileRequest(&data); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	profile, err := o.profileStore.GetProfile(data.Name)
	if err != nil && !errors.Is(err, ariesstorage.ErrDataNotFound) {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	if profile != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("profile %s already exists", profile.Name))

		return
	}

	profile, err = o.createIssuerProfile(&data)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	err = o.profileStore.SaveProfile(profile)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, profile)
}

// RetrieveIssuerProfile swagger:route GET /profile/{id} issuer retrieveProfileReq
//
// Retrieves issuer profile.
//
// Responses:
//    default: genericError
//        200: issuerProfileRes
func (o *Operation) getIssuerProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)["id"]

	profileResponseJSON, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		if errors.Is(err, errProfileNotFound) {
			commhttp.WriteErrorResponse(rw, http.StatusNotFound, "Failed to find the profile")

			return
		}

		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, profileResponseJSON)
}

// DeleteIssuerProfile swagger:route DELETE /profile/{id} issuer deleteIssuerProfileReq
//
// Deletes issuer profile.
//
// Responses:
// 		default: genericError
//			200: emptyRes
func (o *Operation) deleteIssuerProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)["id"]

	// TODO: https://github.com/trustbloc/edge-service/issues/508 delete the edv vault

	err := o.profileStore.DeleteProfile(profileID)

	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}
}

// StoreVerifiableCredential swagger:route POST /store issuer storeCredentialReq
//
// Stores a credential.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) storeCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	data := &StoreVCRequest{}

	err := json.NewDecoder(req.Body).Decode(&data)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	// TODO https://github.com/trustbloc/edge-service/issues/208 credential is bundled into string type - update
	//  this to json.RawMessage
	vc, err := o.parseAndVerifyVC([]byte(data.Credential))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("unable to unmarshal the VC: %s", err.Error()))
		return
	}
	// TODO https://github.com/trustbloc/edge-service/issues/417 add profileID to the path param rather than the body
	if err = validateRequest(data.Profile, vc.ID); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	o.storeVC(data, vc, rw)
}

// ToDo: data.Credential and vc seem to contain the same data... do they both need to be passed in?
// https://github.com/trustbloc/edge-service/issues/265
func (o *Operation) storeVC(data *StoreVCRequest, vc *verifiable.Credential, rw http.ResponseWriter) {
	doc, err := vcutil.BuildStructuredDocForStorage([]byte(data.Credential))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	encryptedDocument, err := o.buildEncryptedDoc(doc, vc.ID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	profile, err := o.profileStore.GetProfile(data.Profile)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	_, err = o.edvClient.CreateDocument(profile.EDVVaultID, &encryptedDocument, client.WithRequestHeader(
		func(req *http.Request) (*http.Header, error) {
			if len(profile.EDVCapability) != 0 {
				return o.authService.SignHeader(req, profile.EDVCapability, profile.EDVController)
			}

			return nil, nil
		}))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}
}

func (o *Operation) buildEncryptedDoc(structuredDoc *models.StructuredDocument,
	vcID string) (models.EncryptedDocument, error) {
	marshalledStructuredDoc, err := json.Marshal(structuredDoc)
	if err != nil {
		return models.EncryptedDocument{}, err
	}

	jwe, err := o.jweEncrypter.Encrypt(marshalledStructuredDoc)
	if err != nil {
		return models.EncryptedDocument{}, err
	}

	encryptedStructuredDoc, err := jwe.FullSerialize(json.Marshal)
	if err != nil {
		return models.EncryptedDocument{}, err
	}

	vcIDMAC, err := o.macCrypto.ComputeMAC([]byte(vcID), o.macKeyHandle)
	if err != nil {
		return models.EncryptedDocument{}, err
	}

	vcIDIndexValueEncoded := base64.URLEncoding.EncodeToString(vcIDMAC)

	indexedAttribute := models.IndexedAttribute{
		Name:   o.vcIDIndexNameEncoded,
		Value:  vcIDIndexValueEncoded,
		Unique: true,
	}

	indexedAttributeCollection := models.IndexedAttributeCollection{
		Sequence:          0,
		HMAC:              models.IDTypePair{},
		IndexedAttributes: []models.IndexedAttribute{indexedAttribute},
	}

	indexedAttributeCollections := []models.IndexedAttributeCollection{indexedAttributeCollection}

	encryptedDocument := models.EncryptedDocument{
		ID:                          structuredDoc.ID,
		Sequence:                    0,
		JWE:                         []byte(encryptedStructuredDoc),
		IndexedAttributeCollections: indexedAttributeCollections,
	}

	return encryptedDocument, nil
}

// StoreVerifiableCredential swagger:route POST /retrieve issuer retrieveCredentialReq
//
// Retrieves a stored credential.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) retrieveCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	profileName := req.URL.Query().Get("profile")

	if err := validateRequest(profileName, id); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	profile, err := o.profileStore.GetProfile(profileName)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	// TODO (#545): Use TrustBloc EDV server optimization to get full document directly from Query call.
	docURLs, err := o.queryVault(profile.EDVVaultID, profile.EDVCapability, profile.EDVController, id)
	if err != nil {
		// The case where no docs match the given query is handled in o.retrieveCredential.
		// Any other error is unexpected and is handled here.
		if err != errNoDocsMatchQuery {
			commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())
			return
		}
	}

	o.retrieveCredential(rw, profileName, profile.EDVVaultID, docURLs, profile.EDVCapability, profile.EDVController)
}

func (o *Operation) createIssuerProfile(pr *ProfileRequest) (*vcprofile.IssuerProfile, error) {
	var didID, publicKeyID string

	didID, publicKeyID, err := o.commonDID.CreateDID(pr.DIDKeyType, pr.SignatureType,
		pr.DID, pr.DIDPrivateKey, pr.DIDKeyID, crypto.AssertionMethod, pr.UNIRegistrar)
	if err != nil {
		return nil, err
	}

	created := time.Now().UTC()

	edvVaultID, capability, didKey, err := o.createIssuerProfileVault()
	if err != nil {
		return nil, fmt.Errorf("fail to create issuer profile vault: %w", err)
	}

	return &vcprofile.IssuerProfile{DataProfile: &vcprofile.DataProfile{Name: pr.Name, Created: &created, DID: didID,
		SignatureType: pr.SignatureType, SignatureRepresentation: pr.SignatureRepresentation, Creator: publicKeyID},
		URI: pr.URI, EDVCapability: capability, EDVVaultID: edvVaultID, DisableVCStatus: pr.DisableVCStatus,
		OverwriteIssuer: pr.OverwriteIssuer, EDVController: didKey}, nil
}

// createIssuerProfileVault creates the vault associated with the profile
func (o *Operation) createIssuerProfileVault() (string, []byte, string, error) {
	// call auth service to create key
	didKey, err := o.authService.CreateDIDKey()
	if err != nil {
		return "", nil, "", err
	}

	dataVaultConfig := &models.DataVaultConfiguration{Sequence: 0, Controller: didKey, ReferenceID: uuid.New().String(),
		KEK:  models.IDTypePair{ID: uuid.New().URN(), Type: "X25519KeyAgreementKey2019"},
		HMAC: models.IDTypePair{ID: uuid.New().URN(), Type: "Sha256HmacKey2019"}}

	vaultLocationURL, resp, err := o.edvClient.CreateDataVault(dataVaultConfig)
	if err != nil {
		return "", nil, "", fmt.Errorf("fail to create vault in EDV: %w", err)
	}

	edvVaultID := vcutil.GetVaultIDFromURL(vaultLocationURL)

	return edvVaultID, resp, didKey, nil
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

// IssueCredential swagger:route POST /{id}/credentials/issueCredential issuer issueCredentialReq
//
// Issues a credential.
//
// Responses:
//    default: genericError
//        201: verifiableCredentialRes
// nolint: funlen
func (o *Operation) issueCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	// get the issuer profile
	profileID := mux.Vars(req)[profileIDPathParam]

	profile, err := o.profileStore.GetProfile(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid issuer profile - id=%s: err=%s",
			profileID, err.Error()))

		return
	}

	// get the request
	cred := IssueCredentialRequest{}

	err = json.NewDecoder(req.Body).Decode(&cred)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	// validate options
	if err = validateIssueCredOptions(cred.Opts); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	// validate the VC (ignore the proof)
	credential, err := verifiable.ParseCredential(cred.Credential, verifiable.WithDisabledProofCheck())
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to validate credential: %s", err.Error()))

		return
	}

	if !profile.DisableVCStatus {
		// set credential status
		credential.Status, err = o.vcStatusManager.CreateStatusID(profile.DataProfile)
		if err != nil {
			commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to add credential status:"+
				" %s", err.Error()))

			return
		}

		credential.Context = append(credential.Context, cslstatus.Context)
	}

	// update context
	vcutil.UpdateSignatureTypeContext(credential, profile)

	// update credential issuer
	vcutil.UpdateIssuer(credential, profile)

	// sign the credential
	signedVC, err := o.crypto.SignCredential(profile.DataProfile, credential, getIssuerSigningOpts(cred.Opts)...)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential:"+
			" %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, signedVC)
}

//nolint:funlen
// composeAndIssueCredential swagger:route POST /{id}/credentials/composeAndIssueCredential issuer composeCredentialReq
//
// Composes and Issues a credential.
//
// Responses:
//    default: genericError
//        201: verifiableCredentialRes
func (o *Operation) composeAndIssueCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)[profileIDPathParam]

	profile, err := o.profileStore.GetProfile(id)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid issuer profile: %s", err.Error()))

		return
	}

	// get the request
	composeCredReq := ComposeCredentialRequest{}

	err = json.NewDecoder(req.Body).Decode(&composeCredReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	// create the verifiable credential
	credential, err := buildCredential(&composeCredReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to build credential:"+
			" %s", err.Error()))

		return
	}

	if !profile.DisableVCStatus {
		// set credential status
		credential.Status, err = o.vcStatusManager.CreateStatusID(profile.DataProfile)
		if err != nil {
			commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to add credential status:"+
				" %s", err.Error()))

			return
		}

		credential.Context = append(credential.Context, cslstatus.Context)
	}

	// update context
	vcutil.UpdateSignatureTypeContext(credential, profile)

	// update credential issuer
	vcutil.UpdateIssuer(credential, profile)

	// prepare signing options from request options
	opts, err := getComposeSigningOpts(&composeCredReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to prepare signing options:"+
			" %s", err.Error()))

		return
	}

	// sign the credential
	signedVC, err := o.crypto.SignCredential(profile.DataProfile, credential, opts...)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential:"+
			" %s", err.Error()))

		return
	}

	// response
	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, signedVC)
}

// nolint: funlen
func buildCredential(composeCredReq *ComposeCredentialRequest) (*verifiable.Credential, error) {
	// create the verifiable credential
	credential := &verifiable.Credential{}

	var err error

	// set credential data
	credential.Context, err = vcutil.GetContextsFromJSONRaw(composeCredReq.CredentialFormatOptions)
	if err != nil {
		return nil, err
	}

	if composeCredReq.IssuanceDate != nil {
		credential.Issued = util.NewTime(*composeCredReq.IssuanceDate)
	}

	if composeCredReq.ExpirationDate != nil {
		credential.Expired = util.NewTime(*composeCredReq.ExpirationDate)
	}

	// set default type, if request doesn't contain the type
	credential.Types = []string{"VerifiableCredential"}
	if len(composeCredReq.Types) != 0 {
		credential.Types = composeCredReq.Types
	}

	// set subject
	credentialSubject := make(map[string]interface{})

	if composeCredReq.Claims != nil {
		err = json.Unmarshal(composeCredReq.Claims, &credentialSubject)
		if err != nil {
			return nil, err
		}
	}

	credentialSubject["id"] = composeCredReq.Subject
	credential.Subject = credentialSubject

	// set issuer
	credential.Issuer = verifiable.Issuer{
		ID: composeCredReq.Issuer,
	}

	// set terms of use
	termsOfUse, err := vcutil.DecodeTypedIDFromJSONRaw(composeCredReq.TermsOfUse)
	if err != nil {
		return nil, err
	}

	credential.TermsOfUse = termsOfUse

	// set evidence
	if composeCredReq.Evidence != nil {
		evidence := make(map[string]interface{})

		err := json.Unmarshal(composeCredReq.Evidence, &evidence)
		if err != nil {
			return nil, err
		}

		credential.Evidence = evidence
	}

	return credential, nil
}

func getComposeSigningOpts(composeCredReq *ComposeCredentialRequest) ([]crypto.SigningOpts, error) {
	var proofFormatOptions struct {
		KeyID   string     `json:"kid,omitempty"`
		Purpose string     `json:"proofPurpose,omitempty"`
		Created *time.Time `json:"created,omitempty"`
	}

	if composeCredReq.ProofFormatOptions != nil {
		err := json.Unmarshal(composeCredReq.ProofFormatOptions, &proofFormatOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare signing opts: %w", err)
		}
	}

	representation := "jws"
	if composeCredReq.ProofFormat != "" {
		representation = composeCredReq.ProofFormat
	}

	return []crypto.SigningOpts{
		crypto.WithPurpose(proofFormatOptions.Purpose),
		crypto.WithVerificationMethod(proofFormatOptions.KeyID),
		crypto.WithSigningRepresentation(representation),
		crypto.WithCreated(proofFormatOptions.Created),
	}, nil
}

func getIssuerSigningOpts(opts *IssueCredentialOptions) []crypto.SigningOpts {
	var signingOpts []crypto.SigningOpts

	if opts != nil {
		// verification method takes priority
		verificationMethod := opts.VerificationMethod

		if verificationMethod == "" {
			verificationMethod = opts.AssertionMethod
		}

		signingOpts = []crypto.SigningOpts{
			crypto.WithVerificationMethod(verificationMethod),
			crypto.WithPurpose(opts.ProofPurpose),
			crypto.WithCreated(opts.Created),
			crypto.WithChallenge(opts.Challenge),
			crypto.WithDomain(opts.Domain),
		}
	}

	return signingOpts
}

// GenerateKeypair swagger:route GET /kms/generatekeypair issuer req
//
// Generates a keypair, stores it in the KMS and returns the public key.
//
// Responses:
//    default: genericError
//        200: generateKeypairResp
func (o *Operation) generateKeypairHandler(rw http.ResponseWriter, req *http.Request) {
	keyID, signKey, err := o.createKey(kms.ED25519Type)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to create key pair: %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusOK)
	commhttp.WriteResponse(rw, &GenerateKeyPairResponse{
		PublicKey: base58.Encode(signKey),
		KeyID:     keyID,
	})
}

func (o *Operation) createKey(keyType kms.KeyType) (string, []byte, error) {
	keyID, _, err := o.kms.Create(keyType)
	if err != nil {
		return "", nil, err
	}

	pubKeyBytes, err := o.kms.ExportPubKeyBytes(keyID)
	if err != nil {
		return "", nil, err
	}

	return keyID, pubKeyBytes, nil
}

func (o *Operation) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	vc, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(o.vdr).PublicKeyFetcher(),
		),
	)

	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (o *Operation) queryVault(vaultID string, capability []byte, vm, vcID string) ([]string, error) {
	vcIDMAC, err := o.macCrypto.ComputeMAC([]byte(vcID), o.macKeyHandle)
	if err != nil {
		return nil, err
	}

	vcIDIndexValueEncoded := base64.URLEncoding.EncodeToString(vcIDMAC)

	var docURLs []string

	err = retry.Retry(func() error {
		var errQueryVault error

		docURLs, errQueryVault = o.edvClient.QueryVault(vaultID, o.vcIDIndexNameEncoded, vcIDIndexValueEncoded,
			client.WithRequestHeader(func(req *http.Request) (*http.Header, error) {
				if len(capability) != 0 {
					return o.authService.SignHeader(req, capability, vm)
				}

				return nil, nil
			}))
		if errQueryVault != nil {
			return errQueryVault
		}

		if len(docURLs) == 0 {
			return errNoDocsMatchQuery
		}

		return nil
	}, o.retryParameters)

	return docURLs, err
}

func (o *Operation) retrieveCredential(rw http.ResponseWriter, profileName, edvVaultID string, docURLs []string,
	capability []byte, vm string) {
	var retrievedVC []byte

	switch len(docURLs) {
	case 0:
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf(`no VC under profile "%s" was found with the given id`, profileName))
	case 1:
		docID := vcutil.GetDocIDFromURL(docURLs[0])

		var err error

		retrievedVC, err = o.retrieveVC(edvVaultID, docID, "retrieving VC", capability, vm)
		if err != nil {
			commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())

			return
		}
	default:
		// Multiple VCs were found with the same id. This is technically possible under the right circumstances
		// when storing the same VC multiples times in a store provider that follows an "eventually consistent"
		// consistency model. If they are all the same, then just return the first one arbitrarily.
		// ToDo: If the multiple VCs with the same ID all are identical then delete the extras and leave only one.
		// https://github.com/trustbloc/edge-service/issues/262
		var err error

		var statusCode int

		retrievedVC, statusCode, err = o.verifyMultipleMatchingVCsAreIdentical(edvVaultID, docURLs, capability, vm)
		if err != nil {
			commhttp.WriteErrorResponse(rw, statusCode, err.Error())

			return
		}
	}

	_, err := rw.Write(retrievedVC)
	if err != nil {
		logger.Errorf("Failed to write response for document retrieval success: %s",
			err.Error())

		return
	}
}

func (o *Operation) verifyMultipleMatchingVCsAreIdentical(edvVaultID string, docURLs []string,
	capability []byte, vm string) ([]byte, int, error) {
	var retrievedVCs [][]byte

	for _, docURL := range docURLs {
		docID := vcutil.GetDocIDFromURL(docURL)

		retrievedVC, err := o.retrieveVC(edvVaultID, docID, "determining if the multiple VCs "+
			"matching the given ID are the same", capability, vm)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}

		retrievedVCs = append(retrievedVCs, retrievedVC)
	}

	for i := 1; i < len(retrievedVCs); i++ {
		if !bytes.Equal(retrievedVCs[0], retrievedVCs[i]) {
			return nil, http.StatusConflict, errMultipleInconsistentVCsFoundForOneID
		}
	}

	return retrievedVCs[0], http.StatusOK, nil
}

func (o *Operation) retrieveVC(edvVaultID, docID, contextErrText string, capability []byte,
	vm string) ([]byte, error) {
	document, err := o.edvClient.ReadDocument(edvVaultID, docID, client.WithRequestHeader(
		func(req *http.Request) (*http.Header, error) {
			if len(capability) != 0 {
				return o.authService.SignHeader(req, capability, vm)
			}

			return nil, nil
		}))
	if err != nil {
		return nil, fmt.Errorf("failed to read document while %s: %s", contextErrText, err)
	}

	encryptedJWE, err := jose.Deserialize(string(document.JWE))
	if err != nil {
		return nil, err
	}

	decryptedDocBytes, err := o.jweDecrypter.Decrypt(encryptedJWE)
	if err != nil {
		return nil, fmt.Errorf("decrypting document failed while "+contextErrText+": %s", err)
	}

	decryptedDoc := models.StructuredDocument{}

	err = json.Unmarshal(decryptedDocBytes, &decryptedDoc)
	if err != nil {
		return nil, fmt.Errorf("decrypted structured document unmarshalling failed "+
			"while "+contextErrText+": %s", err)
	}

	retrievedVC, err := json.Marshal(decryptedDoc.Content["message"])
	if err != nil {
		return nil, fmt.Errorf("failed to marshall VC from decrypted document while "+
			contextErrText+": %s", err)
	}

	return retrievedVC, nil
}

func validateIssueCredOptions(options *IssueCredentialOptions) error {
	if options != nil {
		switch {
		case options.ProofPurpose != "":
			switch options.ProofPurpose {
			case assertionMethod, authentication, capabilityDelegation, capabilityInvocation:
			default:
				return fmt.Errorf("invalid proof option : %s", options.ProofPurpose)
			}
		case options.AssertionMethod != "":
			idSplit := strings.Split(options.AssertionMethod, "#")
			if len(idSplit) != splitAssertionMethodLength {
				return fmt.Errorf("invalid assertion method : %s", idSplit)
			}
		}
	}

	return nil
}
