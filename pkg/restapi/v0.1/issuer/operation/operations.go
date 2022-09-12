/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	commondid "github.com/trustbloc/vcs/pkg/restapi/v0.1/internal/common/did"
	commhttp "github.com/trustbloc/vcs/pkg/restapi/v0.1/internal/common/http"
	vcsstorage "github.com/trustbloc/vcs/pkg/storage"

	"github.com/btcsuite/btcutil/base58"
	"github.com/gorilla/mux"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	cslstatus "github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	"github.com/trustbloc/vcs/pkg/internal/common/support"
)

const (
	logModuleName      = "vcs-issuer-restapi"
	profileIDPathParam = "profileID"

	// Issuer endpoints.
	createProfileEndpoint          = "/profile"
	getProfileEndpoint             = createProfileEndpoint + "/{id}"
	deleteProfileEndpoint          = createProfileEndpoint + "/{id}"
	storeCredentialEndpoint        = "/store"
	retrieveCredentialEndpoint     = "/retrieve"
	credentialStatus               = "/status"
	credentialStatusEndpoint       = "/" + "{" + profileIDPathParam + "}" + credentialStatus + "/{id}"
	credentialsBasePath            = "/" + "{" + profileIDPathParam + "}" + "/credentials"
	updateCredentialStatusEndpoint = credentialsBasePath + credentialStatus
	issueCredentialPath            = credentialsBasePath + "/issue"
	composeAndIssueCredentialPath  = credentialsBasePath + "/composeAndIssueCredential"
	kmsBasePath                    = "/kms"
	generateKeypairPath            = kmsBasePath + "/generatekeypair"

	cslSize = 1000

	invalidRequestErrMsg = "Invalid request"

	// Supported proof purpose.
	assertionMethod      = "assertionMethod"
	authentication       = "authentication"
	capabilityDelegation = "capabilityDelegation"
	capabilityInvocation = "capabilityInvocation"

	splitAssertionMethodLength = 2

	defaultKeyType = kms.ED25519Type
)

var logger = log.New("vcs-issuer-restapi")

var errProfileNotFound = errors.New("specified profile ID does not exist")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type vcStatusManager interface {
	CreateStatusID(signer *vc.Signer, url string) (*verifiable.TypedID, error)
	UpdateVC(v *verifiable.Credential, signer *vc.Signer, status bool) error
	GetRevocationListVC(id string) ([]byte, error)
}

type keyManager interface {
	kms.KeyManager
}

type commonDID interface {
	CreateDID(keyType, signatureType, did, privateKey, keyID string) (string, string, error)
}

// New returns CreateCredential instance.
func New(config *Config) (*Operation, error) {
	vcskmswrapper := vcskms.NewAriesKeyManager(config.KeyManager, config.Crypto)

	c := crypto.New(config.VDRI, config.DocumentLoader)

	vcStatusManager, err := cslstatus.New(config.StoreProvider, cslSize, c, config.DocumentLoader)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new csl status: %w", err)
	}

	profileStore, err := config.StoreProvider.OpenIssuerProfileStore()
	if err != nil {
		return nil, err
	}

	vcStore, err := config.StoreProvider.OpenVCStore()
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		profileStore:    profileStore,
		vcskmswrapper:   vcskmswrapper,
		kms:             config.KeyManager,
		vdr:             config.VDRI,
		crypto:          c,
		vcStatusManager: vcStatusManager,
		domain:          config.Domain,
		hostURL:         config.HostURL,
		commonDID: commondid.New(&commondid.Config{
			VDRI: config.VDRI, KeyManager: config.KeyManager,
			Domain: config.Domain, TLSConfig: config.TLSConfig,
			DIDAnchorOrigin: config.DIDAnchorOrigin,
		}),
		documentLoader: config.DocumentLoader,
		storeProvider:  config.StoreProvider,
		vcStore:        vcStore,
	}

	return svc, nil
}

// Config defines configuration for vcs operations.
type Config struct {
	StoreProvider   vcsstorage.Provider
	KeyManager      keyManager
	VDRI            vdrapi.Registry
	HostURL         string
	Domain          string
	TLSConfig       *tls.Config
	Crypto          ariescrypto.Crypto
	DIDAnchorOrigin string
	DocumentLoader  ld.DocumentLoader
}

// Operation defines handlers for issuer service.
type Operation struct {
	profileStore    vcsstorage.IssuerProfileStore
	vcskmswrapper   vcskms.VCSKeyManager
	kms             keyManager
	vdr             vdrapi.Registry
	crypto          *crypto.Crypto
	vcStatusManager vcStatusManager
	domain          string
	hostURL         string
	commonDID       commonDID
	documentLoader  ld.DocumentLoader
	storeProvider   vcsstorage.Provider
	vcStore         vcsstorage.VCStore
}

// GetRESTHandlers get all controller API handler available for this service.
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

// RetrieveCredentialStatus swagger:route GET /{id}/status/{statusID} issuer retrieveCredentialStatusReq
//
// Retrieves the credential status.
//
// Responses:
//    default: genericError
//        200: retrieveCredentialStatusResp
func (o *Operation) retrieveCredentialStatus(rw http.ResponseWriter, req *http.Request) {
	revocationListVCBytes, err := o.vcStatusManager.GetRevocationListVC(o.hostURL + req.RequestURI)
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

// UpdateCredentialStatus swagger:route POST /{id}/credentials/status issuer updateCredentialStatusReq
//
// Updates credential status.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) updateCredentialStatusHandler(rw http.ResponseWriter, req *http.Request) { //nolint: funlen,gocyclo
	profileID := mux.Vars(req)[profileIDPathParam]

	profile, err := o.profileStore.Get(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid issuer profile - id=%s: err=%s",
			profileID, err.Error()))

		return
	}

	if profile.DisableVCStatus {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("vc status is disabled for profile %s", profile.Name))
		return
	}

	data := UpdateCredentialStatusRequest{}

	err = json.NewDecoder(req.Body).Decode(&data)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to decode request received: %s", err.Error()))

		return
	}

	if data.CredentialStatus.Type != cslstatus.StatusList2021Entry {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("credential status %s not supported", data.CredentialStatus.Type))

		return
	}

	vcBytes, err := o.vcStore.Get(profile.Name, data.CredentialID)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
				fmt.Sprintf(`no VC under profile "%s" was found with the given id`, profile.Name))

			return
		}

		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	credential, err := verifiable.ParseCredential(vcBytes, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to parse credential: %s", err.Error()))

		return
	}

	statusValue, err := strconv.ParseBool(data.CredentialStatus.Status)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to parse status: %s", err.Error()))

		return
	}

	signer := &vc.Signer{
		DID:                     profile.DID,
		Creator:                 profile.Creator,
		SignatureType:           vc.SignatureType(profile.SignatureType),
		SignatureRepresentation: profile.SignatureRepresentation,
		KMS:                     o.vcskmswrapper,
	}

	if err := o.vcStatusManager.UpdateVC(credential, signer, statusValue); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
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
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	if err := validateProfileRequest(&data); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	_, err := o.profileStore.Get(data.Name)
	if err == nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("profile %s already exists", data.Name))

		return
	} else if !errors.Is(err, ariesstorage.ErrDataNotFound) {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	profile, err := o.createIssuerProfile(&data)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	err = o.profileStore.Put(*profile)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, http.StatusCreated, profile)
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

	profileResponseJSON, err := o.profileStore.Get(profileID)
	if err != nil {
		if errors.Is(err, errProfileNotFound) {
			commhttp.WriteErrorResponse(rw, http.StatusNotFound, "Failed to find the profile")

			return
		}

		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, http.StatusOK, profileResponseJSON)
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

	err := o.profileStore.Delete(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, http.StatusOK, nil)
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

	// TODO https://github.com/trustbloc/vcs/issues/208 credential is bundled into string type - update
	//  this to json.RawMessage
	credential, err := o.parseAndVerifyVC([]byte(data.Credential))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("unable to unmarshal the VC: %s", err.Error()))
		return
	}
	// TODO https://github.com/trustbloc/vcs/issues/417 add profileID to the path param rather than the body
	if err = validateRequest(data.Profile, credential.ID); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	profile, err := o.profileStore.Get(data.Profile)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	err = o.vcStore.Put(profile.Name, credential)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	commhttp.WriteResponse(rw, http.StatusOK, nil)
}

// StoreVerifiableCredential swagger:route POST /retrieve issuer retrieveCredentialReq
//
// Retrieves a stored credential.
//
// Responses:
//    default: genericError
//        200: emptyRes
func (o *Operation) retrieveCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	vcID := req.URL.Query().Get("id")
	profileName := req.URL.Query().Get("profile")

	if err := validateRequest(profileName, vcID); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	profile, err := o.profileStore.Get(profileName)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	vcBytes, err := o.vcStore.Get(profileName, vcID)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
				fmt.Sprintf(`no VC under profile "%s" was found with the given id`, profile.Name))

			return
		}

		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	commhttp.WriteResponseBytes(rw, http.StatusOK, vcBytes)
}

func (o *Operation) createIssuerProfile(pr *ProfileRequest) (*vcsstorage.IssuerProfile, error) {
	var didID, publicKeyID string

	didID, publicKeyID, err := o.commonDID.CreateDID(pr.DIDKeyType, pr.SignatureType,
		pr.DID, pr.DIDPrivateKey, pr.DIDKeyID)
	if err != nil {
		return nil, err
	}

	created := time.Now().UTC()

	return &vcsstorage.IssuerProfile{
		DataProfile: vcsstorage.DataProfile{
			Name: pr.Name, Created: &created, DID: didID,
			SignatureType: pr.SignatureType, SignatureRepresentation: pr.SignatureRepresentation, Creator: publicKeyID,
		},
		URI: pr.URI, DisableVCStatus: pr.DisableVCStatus,
		OverwriteIssuer: pr.OverwriteIssuer,
	}, nil
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
		return fmt.Errorf("invalid uri: %w", err)
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

// IssueCredential swagger:route POST /{id}/credentials/issue issuer issueCredentialReq
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

	profile, err := o.profileStore.Get(profileID)
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

	vcSchema := verifiable.JSONSchemaLoader(verifiable.WithDisableRequiredField("issuanceDate"))

	// validate the VC (ignore the proof and issuanceDate)
	credential, err := verifiable.ParseCredential(cred.Credential, verifiable.WithDisabledProofCheck(),
		verifiable.WithSchema(vcSchema),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to validate credential: %s", err.Error()))

		return
	}
	signer := &vc.Signer{
		DID:                     profile.DID,
		Creator:                 profile.Creator,
		SignatureType:           vc.SignatureType(profile.SignatureType),
		SignatureRepresentation: profile.SignatureRepresentation,
		KMS:                     o.vcskmswrapper,
	}

	if !profile.DisableVCStatus {
		// set credential status
		credential.Status, err = o.vcStatusManager.CreateStatusID(signer,
			o.hostURL+"/"+profileID+credentialStatus)
		if err != nil {
			commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to add credential status:"+
				" %s", err.Error()))

			return
		}

		credential.Context = append(credential.Context, cslstatus.Context)
	}

	// update context
	vcutil.UpdateSignatureTypeContext(credential, signer.SignatureType)

	// update credential issuer
	vcutil.UpdateIssuer(credential, profile.DID, profile.Name, profile.OverwriteIssuer)

	// sign the credential
	signedVC, err := o.crypto.SignCredential(signer, credential, getIssuerSigningOpts(cred.Opts)...)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential:"+
			" %s", err.Error()))

		return
	}

	commhttp.WriteResponse(rw, http.StatusCreated, signedVC)
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

	profile, err := o.profileStore.Get(id)
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
		signer := &vc.Signer{
			DID:                     profile.DID,
			Creator:                 profile.Creator,
			SignatureType:           vc.SignatureType(profile.SignatureType),
			SignatureRepresentation: profile.SignatureRepresentation,
			KMS:                     o.vcskmswrapper,
		}
		// set credential status
		credential.Status, err = o.vcStatusManager.CreateStatusID(signer,
			o.hostURL+"/"+id+credentialStatus)
		if err != nil {
			commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to add credential status:"+
				" %s", err.Error()))

			return
		}

		credential.Context = append(credential.Context, cslstatus.Context)
	}

	// update context
	vcutil.UpdateSignatureTypeContext(credential, vc.SignatureType(profile.SignatureType))

	// update credential issuer
	vcutil.UpdateIssuer(credential, profile.DID, profile.Name, profile.OverwriteIssuer)

	// prepare signing options from request options
	opts, err := getComposeSigningOpts(&composeCredReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to prepare signing options:"+
			" %s", err.Error()))

		return
	}

	signer := &vc.Signer{
		DID:                     profile.DID,
		Creator:                 profile.Creator,
		SignatureType:           vc.SignatureType(profile.SignatureType),
		SignatureRepresentation: profile.SignatureRepresentation,
		KMS:                     o.vcskmswrapper,
	}

	// sign the credential
	signedVC, err := o.crypto.SignCredential(signer, credential, opts...)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential:"+
			" %s", err.Error()))

		return
	}

	// response
	commhttp.WriteResponse(rw, http.StatusCreated, signedVC)
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
	var request GenerateKeyPairRequest

	err := json.NewDecoder(req.Body).Decode(&request)

	switch {
	case errors.Is(err, io.EOF) || request.KeyType == "":
		request.KeyType = defaultKeyType
	case err != nil:
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	keyID, signKey, err := o.createKey(request.KeyType)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to create key pair: %s", err.Error()))

		return
	}

	commhttp.WriteResponse(rw, http.StatusOK, &GenerateKeyPairResponse{
		PublicKey: base58.Encode(signKey),
		KeyID:     keyID,
	})
}

func (o *Operation) createKey(keyType kms.KeyType) (string, []byte, error) {
	keyID, _, err := o.kms.Create(keyType)
	if err != nil {
		return "", nil, err
	}

	pubKeyBytes, _, err := o.kms.ExportPubKeyBytes(keyID)
	if err != nil {
		return "", nil, err
	}

	return keyID, pubKeyBytes, nil
}

func (o *Operation) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	vc, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(o.vdr).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader),
	)
	if err != nil {
		return nil, err
	}

	return vc, nil
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
		case options.CredentialStatus.Type != "" && options.CredentialStatus.Type != cslstatus.StatusList2021Entry:
			return fmt.Errorf("not supported credential status type : %s", options.CredentialStatus.Type)
		}
	}

	return nil
}
