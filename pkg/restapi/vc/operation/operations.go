/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
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
	"github.com/google/tink/go/keyset"
	"github.com/gorilla/mux"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	log "github.com/sirupsen/logrus"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edv/pkg/restapi/edv/edverrors"
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
	didclient "github.com/trustbloc/trustbloc-did-method/pkg/did"
	didmethodoperation "github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"

	"github.com/trustbloc/edge-service/internal/cryptosetup"
	"github.com/trustbloc/edge-service/pkg/client/uniregistrar"
	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
)

const (
	credentialStoreName = "credential"

	profileIDPathParam = "profileID"

	// issuer endpoints
	createProfileEndpoint          = "/profile"
	getProfileEndpoint             = createProfileEndpoint + "/{id}"
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

	// holder endpoints
	holderProfileEndpoint    = "/holder/profile"
	getHolderProfileEndpoint = holderProfileEndpoint + "/" + "{" + profileIDPathParam + "}"
	signPresentationEndpoint = "/" + "{" + profileIDPathParam + "}" + "/prove/presentations"

	// verifier endpoints
	verifierBasePath                  = "/verifier"
	credentialsVerificationEndpoint   = verifierBasePath + "/credentials"
	presentationsVerificationEndpoint = verifierBasePath + "/presentations"

	successMsg = "success"
	cslSize    = 50

	invalidRequestErrMsg = "Invalid request"

	// credential verification checks
	proofCheck  = "proof"
	statusCheck = "status"

	// supported proof purpose
	assertionMethod      = "assertionMethod"
	authentication       = "authentication"
	capabilityDelegation = "capabilityDelegation"
	capabilityInvocation = "capabilityInvocation"

	// modes
	issuerMode   = "issuer"
	verifierMode = "verifier"
	holderMode   = "holder"
	combinedMode = "combined"

	recoveryKey1 = "recovery-key"

	// proof data keys
	challenge          = "challenge"
	domain             = "domain"
	proofPurpose       = "proofPurpose"
	verificationMethod = "verificationMethod"

	jsonWebSignature2020Context = "https://trustbloc.github.io/context/vc/credentials-v1.jsonld"
)

// nolint: gochecknoglobals
var signatureKeyTypeMap = map[string]string{
	crypto.Ed25519Signature2018: crypto.Ed25519VerificationKey2018,
	crypto.JSONWebSignature2020: crypto.JwsVerificationKey2020,
}

var errProfileNotFound = errors.New("specified profile ID does not exist")

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
	CreateStatusID() (*verifiable.TypedID, error)
	UpdateVCStatus(v *verifiable.Credential, profile *vcprofile.DataProfile, status, statusReason string) error
	GetCSL(id string) (*cslstatus.CSL, error)
}

// EDVClient interface to interact with edv client
type EDVClient interface {
	CreateDataVault(config *models.DataVaultConfiguration) (string, error)
	CreateDocument(vaultID string, document *models.EncryptedDocument) (string, error)
	ReadDocument(vaultID, docID string) (*models.EncryptedDocument, error)
	QueryVault(vaultID string, query *models.Query) ([]string, error)
}

type keyManager interface {
	kms.KeyManager
	ExportPubKeyBytes(id string) ([]byte, error)
	ImportPrivateKey(privKey interface{}, kt kms.KeyType, opts ...localkms.PrivateKeyOpts) (string, *keyset.Handle, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type didBlocClient interface {
	CreateDID(domain string, opts ...didclient.CreateDIDOption) (*ariesdid.Doc, error)
}

type uniRegistrarClient interface {
	CreateDID(driverURL string, opts ...uniregistrar.CreateDIDOption) (string, []didmethodoperation.Key, error)
}

// New returns CreateCredential instance
func New(config *Config) (*Operation, error) {
	credentialStore, err := prepareCredentialStore(config)
	if err != nil {
		return nil, err
	}

	c := crypto.New(config.KeyManager, config.Crypto, config.VDRI)

	vcStatusManager, err := cslstatus.New(config.StoreProvider, config.HostURL+credentialStatus, cslSize, c)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new csl status: %w", err)
	}

	jweEncrypter, jweDecrypter, err := cryptosetup.PrepareJWECrypto(config.KeyManager, config.StoreProvider,
		jose.A256GCM, kms.ECDHES256AES256GCMType)
	if err != nil {
		return nil, err
	}

	kh, vcIDIndexNameMACEncoded, err :=
		cryptosetup.PrepareMACCrypto(config.KeyManager, config.StoreProvider, config.Crypto, kms.HMACSHA256Tag256Type)
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		profileStore:         vcprofile.New(credentialStore),
		edvClient:            config.EDVClient,
		kms:                  config.KeyManager,
		vdri:                 config.VDRI,
		crypto:               c,
		jweEncrypter:         jweEncrypter,
		jweDecrypter:         jweDecrypter,
		vcStatusManager:      vcStatusManager,
		didBlocClient:        didclient.New(didclient.WithTLSConfig(config.TLSConfig)),
		domain:               config.Domain,
		httpClient:           &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		HostURL:              config.HostURL,
		uniRegistrarClient:   uniregistrar.New(uniregistrar.WithTLSConfig(config.TLSConfig)),
		macKeyHandle:         kh,
		macCrypto:            config.Crypto,
		vcIDIndexNameEncoded: vcIDIndexNameMACEncoded,
	}

	return svc, nil
}

func prepareCredentialStore(config *Config) (storage.Store, error) {
	err := config.StoreProvider.CreateStore(credentialStoreName)
	if err != nil {
		if err != storage.ErrDuplicateStore {
			return nil, err
		}
	}

	return config.StoreProvider.OpenStore(credentialStoreName)
}

// Config defines configuration for vcs operations
type Config struct {
	StoreProvider      storage.Provider
	KMSSecretsProvider ariesstorage.Provider
	EDVClient          EDVClient
	KeyManager         keyManager
	VDRI               vdriapi.Registry
	HostURL            string
	Domain             string
	Mode               string
	TLSConfig          *tls.Config
	Crypto             ariescrypto.Crypto
}

// Operation defines handlers for Edge service
type Operation struct {
	profileStore         *vcprofile.Profile
	edvClient            EDVClient
	kms                  keyManager
	vdri                 vdriapi.Registry
	crypto               *crypto.Crypto
	jweEncrypter         jose.Encrypter
	jweDecrypter         jose.Decrypter
	vcStatusManager      vcStatusManager
	didBlocClient        didBlocClient
	domain               string
	httpClient           httpClient
	HostURL              string
	uniRegistrarClient   uniRegistrarClient
	macKeyHandle         *keyset.Handle
	macCrypto            ariescrypto.Crypto
	vcIDIndexNameEncoded string
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers(mode string) ([]Handler, error) {
	switch mode {
	case verifierMode:
		return o.verifierHandlers(), nil
	case issuerMode:
		return o.issuerHandlers(), nil
	case holderMode:
		return o.holderHandlers(), nil
	case combinedMode:
		vh := o.verifierHandlers()
		ih := o.issuerHandlers()
		hh := o.holderHandlers()

		handlers := append(vh, ih...)

		return append(handlers, hh...), nil
	default:
		return nil, fmt.Errorf("invalid operation mode: %s", mode)
	}
}

func (o *Operation) verifierHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(credentialsVerificationEndpoint, http.MethodPost, o.verifyCredentialHandler),
		support.NewHTTPHandler(presentationsVerificationEndpoint, http.MethodPost,
			o.verifyPresentationHandler),
	}
}

func (o *Operation) issuerHandlers() []Handler {
	return []Handler{
		// issuer profile
		support.NewHTTPHandler(createProfileEndpoint, http.MethodPost, o.createIssuerProfileHandler),
		support.NewHTTPHandler(getProfileEndpoint, http.MethodGet, o.getIssuerProfileHandler),

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

func (o *Operation) holderHandlers() []Handler {
	return []Handler{
		// holder profile
		support.NewHTTPHandler(holderProfileEndpoint, http.MethodPost, o.createHolderProfileHandler),
		support.NewHTTPHandler(getHolderProfileEndpoint, http.MethodGet, o.getHolderProfileHandler),
		support.NewHTTPHandler(signPresentationEndpoint, http.MethodPost, o.signPresentationHandler),
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
	csl, err := o.vcStatusManager.GetCSL(o.HostURL + req.RequestURI)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to get credential status list: %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusOK)
	o.writeResponse(rw, csl)
}

func (o *Operation) checkVCStatus(vclID, vcID string) (*VerifyCredentialResponse, error) {
	vcResp := &VerifyCredentialResponse{
		Verified: false}

	req, err := http.NewRequest(http.MethodGet, vclID, nil)
	if err != nil {
		return nil, err
	}

	resp, err := o.sendHTTPRequest(req, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var csl cslstatus.CSL
	if err := json.Unmarshal(resp, &csl); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp to csl: %w", err)
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

func (o *Operation) sendHTTPRequest(req *http.Request, status int) ([]byte, error) {
	resp, err := o.httpClient.Do(req)
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
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request received: %s", err.Error()))
		return
	}

	// TODO https://github.com/trustbloc/edge-service/issues/208 credential is bundled into string type - update
	//  this to json.RawMessage
	vc, err := o.parseAndVerifyVC([]byte(data.Credential))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("unable to unmarshal the VC: %s", err.Error()))
		return
	}

	// get profile
	profile, err := o.profileStore.GetProfile(vc.Issuer.CustomFields["name"].(string))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to get profile: %s", err.Error()))
		return
	}

	if profile.DisableVCStatus {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("vc status is disabled for profile %s", profile.Name))
		return
	}

	if err := o.vcStatusManager.UpdateVCStatus(vc, profile, data.Status, data.StatusReason); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to update vc status: %s", err.Error()))
		return
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
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	if err := validateProfileRequest(&data); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	profile, err := o.createIssuerProfile(&data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	err = o.profileStore.SaveProfile(profile)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	// create the vault associated with the profile
	_, err = o.edvClient.CreateDataVault(&models.DataVaultConfiguration{ReferenceID: profile.Name})
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	rw.WriteHeader(http.StatusCreated)
	o.writeResponse(rw, profile)
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
			o.writeErrorResponse(rw, http.StatusNotFound, "Failed to find the profile")

			return
		}

		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	o.writeResponse(rw, profileResponseJSON)
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
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	// TODO https://github.com/trustbloc/edge-service/issues/208 credential is bundled into string type - update
	//  this to json.RawMessage
	vc, err := o.parseAndVerifyVC([]byte(data.Credential))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("unable to unmarshal the VC: %s", err.Error()))
		return
	}

	// TODO https://github.com/trustbloc/edge-service/issues/417 add profileID to the path param rather than the body
	if err = validateRequest(data.Profile, vc.ID); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	o.storeVC(data, vc, rw)
}

// ToDo: data.Credential and vc seem to contain the same data... do they both need to be passed in?
// https://github.com/trustbloc/edge-service/issues/265
func (o *Operation) storeVC(data *StoreVCRequest, vc *verifiable.Credential, rw http.ResponseWriter) {
	doc, err := o.buildStructuredDoc(data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	encryptedDocument, err := o.buildEncryptedDoc(doc, vc.ID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	_, err = o.edvClient.CreateDocument(data.Profile, &encryptedDocument)

	if err != nil && strings.Contains(err.Error(), edverrors.ErrVaultNotFound.Error()) {
		// create the new vault for this profile, if it doesn't exist
		_, err = o.edvClient.CreateDataVault(&models.DataVaultConfiguration{ReferenceID: data.Profile})
		if err == nil {
			_, err = o.edvClient.CreateDocument(data.Profile, &encryptedDocument)
		}
	}

	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}
}

func (o *Operation) buildStructuredDoc(data *StoreVCRequest) (*models.StructuredDocument, error) {
	edvDocID, err := generateEDVCompatibleID()
	if err != nil {
		return nil, err
	}

	doc := models.StructuredDocument{}
	doc.ID = edvDocID
	doc.Content = make(map[string]interface{})

	credentialBytes := []byte(data.Credential)

	var credentialJSONRawMessage json.RawMessage = credentialBytes

	doc.Content["message"] = credentialJSONRawMessage

	return &doc, nil
}

func (o *Operation) buildEncryptedDoc(structuredDoc *models.StructuredDocument,
	vcID string) (models.EncryptedDocument, error) {
	marshalledStructuredDoc, err := json.Marshal(structuredDoc)
	if err != nil {
		return models.EncryptedDocument{}, err
	}

	jwe, err := o.jweEncrypter.Encrypt(marshalledStructuredDoc, nil)
	if err != nil {
		return models.EncryptedDocument{}, err
	}

	encryptedStructuredDoc, err := jwe.Serialize(json.Marshal)
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

func generateEDVCompatibleID() (string, error) {
	randomBytes := make([]byte, 16)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	base58EncodedUUID := base58.Encode(randomBytes)

	return base58EncodedUUID, nil
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
	profile := req.URL.Query().Get("profile")

	if err := validateRequest(profile, id); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	docURLs, err := o.queryVault(profile, id)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	o.retrieveCredential(rw, profile, docURLs)
}

// nolint: gocyclo,funlen
func (o *Operation) createDIDUniRegistrar(keyType, signatureType, purpose string,
	registrar UNIRegistrar) (string, string, error) {
	var opts []uniregistrar.CreateDIDOption

	publicKeys, selectedKeyID, err := o.createPublicKeys(keyType, signatureType)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did public key: %v", err)
	}

	_, recoveryPubKey, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return "", "", err
	}

	for _, v := range publicKeys {
		opts = append(opts, uniregistrar.WithPublicKey(&didmethodoperation.PublicKey{
			ID: v.ID, Type: v.Type,
			Value:    base64.StdEncoding.EncodeToString(v.Value),
			KeyType:  v.KeyType,
			Encoding: v.Encoding, Usage: v.Usage}))
	}

	opts = append(opts,
		uniregistrar.WithPublicKey(&didmethodoperation.PublicKey{
			ID: recoveryKey1, Type: didclient.JWSVerificationKey2020,
			Value:    base64.StdEncoding.EncodeToString(recoveryPubKey),
			Encoding: didclient.PublicKeyEncodingJwk, Recovery: true}),
		uniregistrar.WithOptions(registrar.Options))

	identifier, keys, err := o.uniRegistrarClient.CreateDID(registrar.DriverURL, opts...)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did doc from uni-registrar: %v", err)
	}

	// TODO https://github.com/trustbloc/edge-service/issues/415 remove check when vendors supporting addKeys feature
	if strings.Contains(identifier, "did:trustbloc") {
		for _, v := range keys {
			if strings.Contains(v.ID, "#"+selectedKeyID) {
				return identifier, v.ID, nil
			}
		}

		return "", "", fmt.Errorf("selected key not found %s", selectedKeyID)
	}

	if strings.Contains(identifier, "did:v1") {
		for _, v := range keys {
			for _, p := range v.Purpose {
				if purpose == p {
					err = o.importKey(v.ID, kms.ED25519Type, base58.Decode(v.PrivateKeyBase58))
					if err != nil {
						return "", "", err
					}

					return identifier, v.ID, nil
				}
			}
		}

		return "", "", fmt.Errorf("did:v1 - not able to find key with purpose %s", purpose)
	}

	// vendors not supporting addKeys feature.
	// return first key public and private
	// TODO https://github.com/trustbloc/edge-service/issues/415 remove when vendors supporting addKeys feature
	err = o.importKey(keys[0].ID, kms.ED25519Type, base58.Decode(keys[0].PrivateKeyBase58))
	if err != nil {
		return "", "", err
	}

	return identifier, keys[0].ID, nil
}

func (o *Operation) importKey(keyID string, keyType kms.KeyType, privateKeyBytes []byte) error {
	split := strings.Split(keyID, "#")

	var privKey interface{}

	switch keyType {
	case kms.ED25519Type:
		privKey = ed25519.PrivateKey(privateKeyBytes)
	default:
		return fmt.Errorf("import key type not supported %s", keyType)
	}

	_, _, err := o.kms.ImportPrivateKey(privKey,
		keyType, localkms.WithKeyID(split[1]))
	if err != nil {
		return fmt.Errorf("failed to import private key: %v", err)
	}

	return nil
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

func (o *Operation) createDID(keyType, signatureType string) (string, string, error) {
	var opts []didclient.CreateDIDOption

	publicKeys, selectedKeyID, err := o.createPublicKeys(keyType, signatureType)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did public key: %v", err)
	}

	_, recoveryPubKey, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return "", "", err
	}

	for _, v := range publicKeys {
		opts = append(opts, didclient.WithPublicKey(v))
	}

	opts = append(opts,
		didclient.WithPublicKey(&didclient.PublicKey{ID: recoveryKey1,
			Type: didclient.JWSVerificationKey2020, Value: recoveryPubKey,
			Encoding: didclient.PublicKeyEncodingJwk, Recovery: true}))

	didDoc, err := o.didBlocClient.CreateDID(o.domain, opts...)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did doc: %v", err)
	}

	publicKeyID, err := getPublicKeyID(didDoc, selectedKeyID, "")
	if err != nil {
		return "", "", err
	}

	return didDoc.ID, publicKeyID, nil
}

func (o *Operation) createIssuerProfile(pr *ProfileRequest) (*vcprofile.DataProfile, error) {
	var didID, publicKeyID string

	didID, publicKeyID, err := o.createProfile(pr.DIDKeyType, pr.SignatureType,
		pr.DID, pr.DIDPrivateKey, pr.DIDKeyID, crypto.AssertionMethod, pr.UNIRegistrar)
	if err != nil {
		return nil, err
	}

	created := time.Now().UTC()

	return &vcprofile.DataProfile{Name: pr.Name, URI: pr.URI, Created: &created, DID: didID,
		SignatureType: pr.SignatureType, SignatureRepresentation: pr.SignatureRepresentation, Creator: publicKeyID,
		DisableVCStatus: pr.DisableVCStatus, OverwriteIssuer: pr.OverwriteIssuer,
	}, nil
}

func (o *Operation) createHolderProfile(pr *HolderProfileRequest) (*vcprofile.HolderProfile, error) {
	var didID, publicKeyID string

	didID, publicKeyID, err := o.createProfile(pr.DIDKeyType, pr.SignatureType, pr.DID,
		pr.DIDPrivateKey, pr.DIDKeyID, crypto.Authentication, pr.UNIRegistrar)
	if err != nil {
		return nil, err
	}

	created := time.Now().UTC()

	return &vcprofile.HolderProfile{
		Name:                    pr.Name,
		Created:                 &created,
		DID:                     didID,
		SignatureType:           pr.SignatureType,
		SignatureRepresentation: pr.SignatureRepresentation,
		Creator:                 publicKeyID,
		OverwriteHolder:         pr.OverwriteHolder,
	}, nil
}

func (o *Operation) createProfile(keyType, signatureType, did, privateKey, keyID, purpose string,
	registrar UNIRegistrar) (string, string, error) {
	var didID string

	var publicKeyID string

	switch {
	case registrar.DriverURL != "":
		var err error
		didID, publicKeyID, err = o.createDIDUniRegistrar(keyType, signatureType, purpose, registrar)

		if err != nil {
			return "", "", err
		}

	case did == "":
		var err error
		didID, publicKeyID, err = o.createDID(keyType, signatureType)

		if err != nil {
			return "", "", err
		}

	case did != "":
		didDoc, err := o.vdri.Resolve(did)
		if err != nil {
			return "", "", fmt.Errorf("failed to resolve did: %v", err)
		}

		didID = didDoc.ID

		if privateKey != "" {
			if err := o.importKey(keyID, kms.ED25519Type, base58.Decode(privateKey)); err != nil {
				return "", "", err
			}
		}

		publicKeyID = keyID
	}

	return didID, publicKeyID, nil
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

func validateHolderProfileRequest(pr *HolderProfileRequest) error {
	if pr.Name == "" {
		return fmt.Errorf("missing profile name")
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

	err := json.NewEncoder(rw).Encode(ErrorResponse{
		Message: msg,
	})

	if err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
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
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid issuer profile - id=%s: err=%s",
			profileID, err.Error()))

		return
	}

	// get the request
	cred := IssueCredentialRequest{}

	err = json.NewDecoder(req.Body).Decode(&cred)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	// validate options
	if err = validateIssueCredOptions(cred.Opts); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	// validate the VC (ignore the proof)
	credential, _, err := verifiable.NewCredential(cred.Credential, verifiable.WithDisabledProofCheck())
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to validate credential: %s", err.Error()))

		return
	}

	if !profile.DisableVCStatus {
		// set credential status
		credential.Status, err = o.vcStatusManager.CreateStatusID()
		if err != nil {
			o.writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to add credential status:"+
				" %s", err.Error()))

			return
		}

		credential.Context = append(credential.Context, cslstatus.Context)
	}

	// update context
	updateContext(credential, profile)

	// update credential issuer
	updateIssuer(credential, profile)

	// sign the credential
	signedVC, err := o.crypto.SignCredential(profile, credential, getIssuerSigningOpts(cred.Opts)...)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential:"+
			" %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusCreated)
	o.writeResponse(rw, signedVC)
}

// nolint funlen
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
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid issuer profile: %s", err.Error()))

		return
	}

	// get the request
	composeCredReq := ComposeCredentialRequest{}

	err = json.NewDecoder(req.Body).Decode(&composeCredReq)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	// create the verifiable credential
	credential, err := buildCredential(&composeCredReq)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to build credential:"+
			" %s", err.Error()))

		return
	}

	if !profile.DisableVCStatus {
		// set credential status
		credential.Status, err = o.vcStatusManager.CreateStatusID()
		if err != nil {
			o.writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to add credential status:"+
				" %s", err.Error()))

			return
		}

		credential.Context = append(credential.Context, cslstatus.Context)
	}

	// update context
	updateContext(credential, profile)

	// update credential issuer
	updateIssuer(credential, profile)

	// prepare signing options from request options
	opts, err := getComposeSigningOpts(&composeCredReq)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to prepare signing options:"+
			" %s", err.Error()))

		return
	}

	// sign the credential
	signedVC, err := o.crypto.SignCredential(profile, credential, opts...)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential:"+
			" %s", err.Error()))

		return
	}

	// response
	rw.WriteHeader(http.StatusCreated)
	o.writeResponse(rw, signedVC)
}

func buildCredential(composeCredReq *ComposeCredentialRequest) (*verifiable.Credential, error) {
	// create the verifiable credential
	credential := &verifiable.Credential{}

	// set credential data
	credential.Context = []string{"https://www.w3.org/2018/credentials/v1"}
	credential.Issued = composeCredReq.IssuanceDate
	credential.Expired = composeCredReq.ExpirationDate

	// set default type, if request doesn't contain the type
	credential.Types = []string{"VerifiableCredential"}
	if len(composeCredReq.Types) != 0 {
		credential.Types = composeCredReq.Types
	}

	// set subject
	credentialSubject := make(map[string]interface{})

	if composeCredReq.Claims != nil {
		err := json.Unmarshal(composeCredReq.Claims, &credentialSubject)
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
	termsOfUse, err := decodeTypedID(composeCredReq.TermsOfUse)
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

func decodeTypedID(typedIDBytes json.RawMessage) ([]verifiable.TypedID, error) {
	if len(typedIDBytes) == 0 {
		return nil, nil
	}

	var singleTypedID verifiable.TypedID

	err := json.Unmarshal(typedIDBytes, &singleTypedID)
	if err == nil {
		return []verifiable.TypedID{singleTypedID}, nil
	}

	var composedTypedID []verifiable.TypedID

	err = json.Unmarshal(typedIDBytes, &composedTypedID)
	if err == nil {
		return composedTypedID, nil
	}

	return nil, err
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
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to create key pair: %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusOK)
	o.writeResponse(rw, &GenerateKeyPairResponse{
		PublicKey: base58.Encode(signKey),
		KeyID:     keyID,
	})
}

// nolint dupl
// VerifyCredential swagger:route POST /verifier/credentials verifier verifyCredentialReq
//
// Verifies a credential.
//
// Responses:
//    default: genericError
//        200: verifyCredentialSuccessResp
//        400: verifyCredentialFailureResp
func (o *Operation) verifyCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	// get the request
	verificationReq := CredentialsVerificationRequest{}

	err := json.NewDecoder(req.Body).Decode(&verificationReq)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	vc, err := verifiable.NewUnverifiedCredential(verificationReq.Credential)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	checks := []string{proofCheck}

	// if req contains checks, then override the default checks
	if verificationReq.Opts != nil && len(verificationReq.Opts.Checks) != 0 {
		checks = verificationReq.Opts.Checks
	}

	var result []CredentialsVerificationCheckResult

	for _, val := range checks {
		switch val {
		case proofCheck:
			err := o.validateCredentialProof(verificationReq.Credential, verificationReq.Opts, false)
			if err != nil {
				result = append(result, CredentialsVerificationCheckResult{
					Check: val,
					Error: err.Error(),
				})
			}
		case statusCheck:
			failureMessage := ""
			if vc.Status != nil && vc.Status.ID != "" {
				ver, err := o.checkVCStatus(vc.Status.ID, vc.ID)

				if err != nil {
					failureMessage = fmt.Sprintf("failed to fetch the status : %s", err.Error())
				} else if !ver.Verified {
					failureMessage = ver.Message
				}
			}

			if failureMessage != "" {
				result = append(result, CredentialsVerificationCheckResult{
					Check: val,
					Error: failureMessage,
				})
			}
		default:
			result = append(result, CredentialsVerificationCheckResult{
				Check: val,
				Error: "check not supported",
			})
		}
	}

	if len(result) == 0 {
		rw.WriteHeader(http.StatusOK)
		o.writeResponse(rw, &CredentialsVerificationSuccessResponse{
			Checks: checks,
		})
	} else {
		rw.WriteHeader(http.StatusBadRequest)
		o.writeResponse(rw, &CredentialsVerificationFailResponse{
			Checks: result,
		})
	}
}

// VerifyPresentation swagger:route POST /verifier/presentations verifier verifyPresentationReq
//
// Verifies a presentation.
//
// Responses:
//    default: genericError
//        200: verifyPresentationSuccessResp
//        400: verifyPresentationFailureResp
func (o *Operation) verifyPresentationHandler(rw http.ResponseWriter, req *http.Request) {
	// get the request
	verificationReq := VerifyPresentationRequest{}

	err := json.NewDecoder(req.Body).Decode(&verificationReq)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	checks := []string{proofCheck}

	// if req contains checks, then override the default checks
	if verificationReq.Opts != nil && len(verificationReq.Opts.Checks) != 0 {
		checks = verificationReq.Opts.Checks
	}

	var result []VerifyPresentationCheckResult

	for _, val := range checks {
		switch val {
		case proofCheck:
			err := o.validatePresentationProof(verificationReq.Presentation, verificationReq.Opts)
			if err != nil {
				result = append(result, VerifyPresentationCheckResult{
					Check: val,
					Error: err.Error(),
				})
			}
		default:
			result = append(result, VerifyPresentationCheckResult{
				Check: val,
				Error: "check not supported",
			})
		}
	}

	if len(result) == 0 {
		rw.WriteHeader(http.StatusOK)
		o.writeResponse(rw, &VerifyPresentationSuccessResponse{
			Checks: checks,
		})
	} else {
		rw.WriteHeader(http.StatusBadRequest)
		o.writeResponse(rw, &VerifyPresentationFailureResponse{
			Checks: result,
		})
	}
}

// CreateHolderProfile swagger:route POST /holder/profile holder holderProfileReq
//
// Creates holder profile.
//
// Responses:
//    default: genericError
//        201: holderProfileRes
func (o *Operation) createHolderProfileHandler(rw http.ResponseWriter, req *http.Request) {
	request := &HolderProfileRequest{}

	if err := json.NewDecoder(req.Body).Decode(request); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	if err := validateHolderProfileRequest(request); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	profile, err := o.profileStore.GetHolderProfile(request.Name)
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	if profile != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("profile %s already exists", profile.Name))

		return
	}

	profile, err = o.createHolderProfile(request)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	err = o.profileStore.SaveHolderProfile(profile)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	rw.WriteHeader(http.StatusCreated)
	o.writeResponse(rw, profile)
}

// RetrieveHolderProfile swagger:route GET /holder/profile/{id} holder retrieveHolderProfileReq
//
// Retrieves holder profile.
//
// Responses:
//    default: genericError
//        200: holderProfileRes
func (o *Operation) getHolderProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[profileIDPathParam]

	fmt.Println(profileID)

	profile, err := o.profileStore.GetHolderProfile(profileID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	o.writeResponse(rw, profile)
}

// SignPresentation swagger:route POST /{id}/prove/presentations holder signPresentationReq
//
// Signs a presentation.
//
// Responses:
//    default: genericError
//        201: signPresentationRes
func (o *Operation) signPresentationHandler(rw http.ResponseWriter, req *http.Request) {
	// get the holder profile
	profileID := mux.Vars(req)[profileIDPathParam]

	profile, err := o.profileStore.GetHolderProfile(profileID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid holder profile - id=%s: err=%s",
			profileID, err.Error()))

		return
	}

	// get the request
	presReq := SignPresentationRequest{}

	err = json.NewDecoder(req.Body).Decode(&presReq)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	presentation, err := verifiable.NewPresentation(presReq.Presentation,
		verifiable.WithDisabledPresentationProofCheck())
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	// update holder
	updateHolder(presentation, profile)

	// sign presentation
	signedVP, err := o.crypto.SignPresentation(profile, presentation, getPresentationSigningOpts(presReq.Opts)...)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign presentation:"+
			" %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusCreated)
	o.writeResponse(rw, signedVP)
}

func getPresentationSigningOpts(opts *SignPresentationOptions) []crypto.SigningOpts {
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

// updateHolder overrides presentation holder form profile.
func updateHolder(presentation *verifiable.Presentation, profile *vcprofile.HolderProfile) {
	if profile.OverwriteHolder || presentation.Holder == "" {
		presentation.Holder = profile.DID
	}
}

func (o *Operation) validateCredentialProof(vcByte []byte, opts *CredentialsVerificationOptions,
	vcInVPValidation bool) error {
	vc, err := o.parseAndVerifyVCStrictMode(vcByte)

	if err != nil {
		return fmt.Errorf("verifiable credential proof validation error : %w", err)
	}

	if len(vc.Proofs) == 0 {
		return errors.New("verifiable credential doesn't contains proof")
	}

	// validate proof challenge and domain
	if opts == nil {
		opts = &CredentialsVerificationOptions{}
	}

	// TODO https://github.com/trustbloc/edge-service/issues/412 figure out the process when vc has more than one proof
	proof := vc.Proofs[0]

	if !vcInVPValidation {
		// validate challenge
		if err := validateProofData(proof, challenge, opts.Challenge); err != nil {
			return err
		}

		// validate domain
		if err := validateProofData(proof, domain, opts.Domain); err != nil {
			return err
		}
	}

	// validate proof purpose
	if err := validateProofPurpose(proof, o.vdri); err != nil {
		return fmt.Errorf("verifiable credential proof purpose validation error : %w", err)
	}

	return nil
}

func (o *Operation) validatePresentationProof(vpByte []byte, opts *VerifyPresentationOptions) error {
	vp, err := o.parseAndVerifyVP(vpByte)

	if err != nil {
		return fmt.Errorf("verifiable presentation proof validation error : %w", err)
	}

	// validate proof challenge and domain
	if opts == nil {
		opts = &VerifyPresentationOptions{}
	}

	var proof verifiable.Proof

	// TODO https://github.com/trustbloc/edge-service/issues/412 figure out the process when vc has more than one proof
	if len(vp.Proofs) != 0 {
		proof = vp.Proofs[0]
	}

	// validate challenge
	if err := validateProofData(proof, challenge, opts.Challenge); err != nil {
		return err
	}

	// validate domain
	if err := validateProofData(proof, domain, opts.Domain); err != nil {
		return err
	}

	// validate proof purpose
	if err := validateProofPurpose(proof, o.vdri); err != nil {
		return fmt.Errorf("verifiable presentation proof purpose validation error : %w", err)
	}

	return nil
}

func (o *Operation) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	vc, _, err := verifiable.NewCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(o.vdri).PublicKeyFetcher(),
		),
	)

	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (o *Operation) parseAndVerifyVCStrictMode(vcBytes []byte) (*verifiable.Credential, error) {
	vc, _, err := verifiable.NewCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(o.vdri).PublicKeyFetcher(),
		),
		verifiable.WithStrictValidation(),
	)

	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (o *Operation) parseAndVerifyVP(vpBytes []byte) (*verifiable.Presentation, error) {
	vp, err := verifiable.NewPresentation(
		vpBytes,
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
		err = o.validateCredentialProof(vcBytes, nil, true)
		if err != nil {
			return nil, err
		}
	}

	return vp, nil
}

func (o *Operation) queryVault(vaultID, vcID string) ([]string, error) {
	vcIDMAC, err := o.macCrypto.ComputeMAC([]byte(vcID), o.macKeyHandle)
	if err != nil {
		return nil, err
	}

	vcIDIndexValueEncoded := base64.URLEncoding.EncodeToString(vcIDMAC)

	return o.edvClient.QueryVault(vaultID, &models.Query{
		Name:  o.vcIDIndexNameEncoded,
		Value: vcIDIndexValueEncoded,
	})
}

func (o *Operation) retrieveCredential(rw http.ResponseWriter, profileName string, docURLs []string) {
	var retrievedVC []byte

	switch len(docURLs) {
	case 0:
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf(`no VC under profile "%s" was found with the given id`, profileName))
	case 1:
		docID := getDocIDFromURL(docURLs[0])

		var err error

		retrievedVC, err = o.retrieveVC(profileName, docID, "retrieving VC")
		if err != nil {
			o.writeErrorResponse(rw, http.StatusInternalServerError, err.Error())

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

		retrievedVC, statusCode, err = o.verifyMultipleMatchingVCsAreIdentical(profileName, docURLs)
		if err != nil {
			o.writeErrorResponse(rw, statusCode, err.Error())

			return
		}
	}

	_, err := rw.Write(retrievedVC)
	if err != nil {
		log.Errorf("Failed to write response for document retrieval success: %s",
			err.Error())

		return
	}
}

func (o *Operation) verifyMultipleMatchingVCsAreIdentical(profileName string, docURLs []string) ([]byte, int, error) {
	var retrievedVCs [][]byte

	for _, docURL := range docURLs {
		docID := getDocIDFromURL(docURL)

		retrievedVC, err := o.retrieveVC(profileName, docID, "determining if the multiple VCs "+
			"matching the given ID are the same")
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

func (o *Operation) retrieveVC(profileName, docID, contextErrText string) ([]byte, error) {
	document, err := o.edvClient.ReadDocument(profileName, docID)
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

func (o *Operation) createPublicKeys(keyType, signatureType string) ([]*didclient.PublicKey, string, error) {
	var publicKeys []*didclient.PublicKey

	// Add Ed25519VerificationKey2018 Ed25519KeyType
	key1ID, pubKeyBytes, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return nil, "", err
	}

	publicKeys = append(publicKeys, &didclient.PublicKey{ID: key1ID, Type: didclient.Ed25519VerificationKey2018,
		Value: pubKeyBytes, Encoding: didclient.PublicKeyEncodingJwk,
		KeyType: didclient.Ed25519KeyType,
		Usage:   []string{didclient.KeyUsageGeneral, didclient.KeyUsageAssertion, didclient.KeyUsageAuth}})

	// Add JWSVerificationKey2020 Ed25519KeyType
	key2ID, pubKeyBytes, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return nil, "", err
	}

	publicKeys = append(publicKeys, &didclient.PublicKey{ID: key2ID, Type: didclient.JWSVerificationKey2020,
		Value: pubKeyBytes, Encoding: didclient.PublicKeyEncodingJwk,
		KeyType: didclient.Ed25519KeyType,
		Usage:   []string{didclient.KeyUsageGeneral, didclient.KeyUsageAssertion, didclient.KeyUsageAuth}})

	// Add JWSVerificationKey2020  ECKeyType
	key3ID, pubKeyBytes, err := o.createKey(kms.ECDSAP256IEEEP1363)
	if err != nil {
		return nil, "", err
	}

	publicKeys = append(publicKeys, &didclient.PublicKey{ID: key3ID, Type: didclient.JWSVerificationKey2020,
		Value: pubKeyBytes, Encoding: didclient.PublicKeyEncodingJwk, KeyType: didclient.P256KeyType,
		Usage: []string{didclient.KeyUsageGeneral, didclient.KeyUsageAssertion, didclient.KeyUsageAuth}})

	if keyType == crypto.Ed25519KeyType &&
		didclient.Ed25519VerificationKey2018 == signatureKeyTypeMap[signatureType] {
		return publicKeys, key1ID, nil
	}

	if keyType == crypto.Ed25519KeyType &&
		didclient.JWSVerificationKey2020 == signatureKeyTypeMap[signatureType] {
		return publicKeys, key2ID, nil
	}

	if keyType == crypto.P256KeyType &&
		didclient.JWSVerificationKey2020 == signatureKeyTypeMap[signatureType] {
		return publicKeys, key3ID, nil
	}

	return nil, "",
		fmt.Errorf("no key found to match key type:%s and signature type:%s", keyType, signatureType)
}

func getPublicKeyID(didDoc *ariesdid.Doc, keyID, signatureType string) (string, error) {
	switch {
	case len(didDoc.PublicKey) > 0:
		var publicKeyID string

		for _, k := range didDoc.PublicKey {
			// TODO https://github.com/trustbloc/edge-service/issues/415 remove when vendors supporting addKeys feature
			if keyID == "" && k.Type == signatureKeyTypeMap[signatureType] {
				publicKeyID = k.ID
				break
			}

			if keyID != "" && strings.Contains(k.ID, "#"+keyID) {
				publicKeyID = k.ID
				break
			}
		}

		// TODO https://github.com/trustbloc/edge-service/issues/140 this is temporary check to support public
		//  key ID's which aren't in DID format: Will be removed [Issue#140]
		if !isDID(publicKeyID) {
			return didDoc.ID + publicKeyID, nil
		}

		return publicKeyID, nil
	case len(didDoc.Authentication) > 0:
		return didDoc.Authentication[0].PublicKey.ID, nil
	default:
		return "", errors.New("public key not found in DID Document")
	}
}

func isDID(str string) bool {
	return strings.HasPrefix(str, "did:")
}

// updateIssuer overrides credential issuer form profile if
// 'profile.OverwriteIssuer=true' or credential issuer is missing
// credential issue will always be DID
func updateIssuer(credential *verifiable.Credential, profile *vcprofile.DataProfile) {
	if profile.OverwriteIssuer || credential.Issuer.ID == "" {
		credential.Issuer = verifiable.Issuer{ID: profile.DID,
			CustomFields: verifiable.CustomFields{"name": profile.Name}}
	}
}

func updateContext(credential *verifiable.Credential, profile *vcprofile.DataProfile) {
	if profile.SignatureType == crypto.JSONWebSignature2020 {
		credential.Context = append(credential.Context, jsonWebSignature2020Context)
	}
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
			if len(idSplit) != 2 {
				return fmt.Errorf("invalid assertion method : %s", idSplit)
			}
		}
	}

	return nil
}

// Given an EDV document URL, returns just the document ID
func getDocIDFromURL(docURL string) string {
	splitBySlashes := strings.Split(docURL, `/`)
	docIDToRetrieve := splitBySlashes[len(splitBySlashes)-1]

	return docIDToRetrieve
}

func validateProofData(proof verifiable.Proof, key, expectedValue string) error {
	actualVal := ""

	val, ok := proof[key]
	if ok {
		actualVal, _ = val.(string) // nolint
	}

	if expectedValue != actualVal {
		return fmt.Errorf("invalid %s in the proof : expected=%s actual=%s", key, expectedValue, actualVal)
	}

	return nil
}

func validateProofPurpose(proof verifiable.Proof, vdri vdriapi.Registry) error {
	purposeVal, ok := proof[proofPurpose]
	if !ok {
		return errors.New("proof doesn't have purpose")
	}

	purpose, ok := purposeVal.(string)
	if !ok {
		return errors.New("proof purpose is not a string")
	}

	verificationMethodVal, ok := proof[verificationMethod]
	if !ok {
		return errors.New("proof doesn't have verification method")
	}

	verificationMethod, ok := verificationMethodVal.(string)
	if !ok {
		return errors.New("proof verification method is not a string")
	}

	return crypto.ValidateProofPurpose(purpose, verificationMethod, vdri)
}
