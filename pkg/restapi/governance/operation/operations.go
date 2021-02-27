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
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	commondid "github.com/trustbloc/edge-service/pkg/restapi/internal/common/did"
	commhttp "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"
	"github.com/trustbloc/edge-service/pkg/restapi/internal/common/vcutil"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

const (
	governanceCtx           = "https://trustbloc.github.io/context/governance/context.jsonld"
	jsonWebSignature2020Ctx = "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"

	profileIDPathParam = "profileID"

	// governance endpoints
	governanceProfileEndpoint = "/governance/profile"
	issueCredentialHandler    = "/governance/" + "{" + profileIDPathParam + "}" + "/issueCredential"
	credentialStatus          = "/governance/status"

	invalidRequestErrMsg = "Invalid request"

	cslSize = 50
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type commonDID interface {
	CreateDID(keyType, signatureType, did, privateKey, keyID, purpose string,
		registrar model.UNIRegistrar) (string, string, error)
}

type vcStatusManager interface {
	CreateStatusID(profile *vcprofile.DataProfile) (*verifiable.TypedID, error)
}

// New returns governance operation instance
func New(config *Config) (*Operation, error) {
	var data []byte

	if config.ClaimsFile != "" {
		var err error

		data, err = ioutil.ReadFile(config.ClaimsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file '%s' : %w", config.ClaimsFile, err)
		}
	}

	p, err := vcprofile.New(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	c := crypto.New(config.KeyManager, config.Crypto, config.VDRI)

	vcStatusManager, err := cslstatus.New(config.StoreProvider, config.HostURL+credentialStatus, cslSize, c)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new csl status: %w", err)
	}

	svc := &Operation{
		profileStore: p,
		commonDID: commondid.New(&commondid.Config{
			VDRI: config.VDRI, KeyManager: config.KeyManager,
			Domain: config.Domain, TLSConfig: config.TLSConfig,
		}),
		crypto:          c,
		vcStatusManager: vcStatusManager,
		claims:          data,
	}

	return svc, nil
}

// Config defines configuration for vcs operations
type Config struct {
	StoreProvider ariesstorage.Provider
	KeyManager    keyManager
	VDRI          vdrapi.Registry
	Domain        string
	TLSConfig     *tls.Config
	Crypto        ariescrypto.Crypto
	HostURL       string
	ClaimsFile    string
}

type keyManager interface {
	kms.KeyManager
}

// Operation defines handlers for Edge service
type Operation struct {
	commonDID       commonDID
	profileStore    *vcprofile.Profile
	crypto          *crypto.Crypto
	vcStatusManager vcStatusManager
	claims          []byte
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		// governance profile
		support.NewHTTPHandler(governanceProfileEndpoint, http.MethodPost, o.createGovernanceProfileHandler),
		support.NewHTTPHandler(issueCredentialHandler, http.MethodPost, o.issueCredentialHandler),
	}
}

// CreateGovernanceProfile swagger:route POST /governance/profile governance governanceProfileReq
//
// Creates governance profile.
//
// Responses:
//    default: genericError
//        201: governanceProfileRes
func (o *Operation) createGovernanceProfileHandler(rw http.ResponseWriter, req *http.Request) {
	request := &GovernanceProfileRequest{}

	if err := json.NewDecoder(req.Body).Decode(request); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	if err := validateGovernanceProfileRequest(request); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	profile, err := o.profileStore.GetGovernanceProfile(request.Name)
	if err != nil && !errors.Is(err, ariesstorage.ErrDataNotFound) {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	if profile != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("profile %s already exists", profile.Name))

		return
	}

	profile, err = o.createGovernanceProfile(request)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	err = o.profileStore.SaveGovernanceProfile(profile)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, profile)
}

// IssueCredential swagger:route POST /{id}/issueCredential governance issueGovernanceCredentialReq
//
// Issues a credential.
//
// Responses:
//    default: genericError
//        201: verifiableCredentialRes
func (o *Operation) issueCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	// get the governance profile
	profileID := mux.Vars(req)[profileIDPathParam]

	profile, err := o.profileStore.GetGovernanceProfile(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid governance profile - id=%s: err=%s",
			profileID, err.Error()))

		return
	}

	// get the request
	credReq := IssueCredentialRequest{}

	err = json.NewDecoder(req.Body).Decode(&credReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	// add DID
	claims := strings.ReplaceAll(string(o.claims), "$DID", credReq.DID)

	// create the verifiable credential
	credential, err := buildCredential(profile.SignatureType, profile.DID, []byte(claims))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("failed to build credential:"+
			" %s", err.Error()))

		return
	}

	// set credential status
	credential.Status, err = o.vcStatusManager.CreateStatusID(profile.DataProfile)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to add credential status:"+
			" %s", err.Error()))

		return
	}

	credential.Context = append(credential.Context, cslstatus.Context)

	// sign the credential
	signedVC, err := o.crypto.SignCredential(profile.DataProfile, credential)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign credential:"+
			" %s", err.Error()))

		return
	}

	// response
	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, signedVC)
}

func (o *Operation) createGovernanceProfile(pr *GovernanceProfileRequest) (*vcprofile.GovernanceProfile, error) {
	var didID, publicKeyID string

	didID, publicKeyID, err := o.commonDID.CreateDID(pr.DIDKeyType, pr.SignatureType, pr.DID,
		pr.DIDPrivateKey, pr.DIDKeyID, crypto.Authentication, pr.UNIRegistrar)
	if err != nil {
		return nil, err
	}

	created := time.Now().UTC()

	return &vcprofile.GovernanceProfile{
		DataProfile: &vcprofile.DataProfile{
			Name:                    pr.Name,
			Created:                 &created,
			DID:                     didID,
			SignatureType:           pr.SignatureType,
			SignatureRepresentation: pr.SignatureRepresentation,
			Creator:                 publicKeyID,
		},
	}, nil
}

func validateGovernanceProfileRequest(pr *GovernanceProfileRequest) error {
	if pr.Name == "" {
		return fmt.Errorf("missing profile name")
	}

	return nil
}

func buildCredential(signatureType, did string, claims []byte) (*verifiable.Credential, error) {
	// create the verifiable credential
	credential := &verifiable.Credential{}

	var err error

	// set credential data
	credential.Context, err = vcutil.GetContextsFromJSONRaw(nil)
	if err != nil {
		return nil, err
	}

	credential.Context = append(credential.Context, governanceCtx)

	if signatureType == crypto.JSONWebSignature2020 {
		credential.Context = append(credential.Context, jsonWebSignature2020Ctx)
	}

	// set default type, if request doesn't contain the type
	credential.Types = []string{"VerifiableCredential", "GovernanceCredential"}

	// set subject
	if len(claims) != 0 {
		credentialSubject := make(map[string]interface{})

		err = json.Unmarshal(claims, &credentialSubject)
		if err != nil {
			return nil, err
		}

		credential.Subject = credentialSubject
	}

	credential.Issued = util.NewTime(time.Now().UTC())

	// set issuer
	credential.Issuer = verifiable.Issuer{
		ID: did,
	}

	return credential, nil
}
