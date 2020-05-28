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
	"net/http"
	"time"

	"github.com/gorilla/mux"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	commondid "github.com/trustbloc/edge-service/pkg/restapi/internal/common/did"
	commhttp "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

const (
	profileIDPathParam = "profileID"

	// holder endpoints
	holderProfileEndpoint    = "/holder/profile"
	getHolderProfileEndpoint = holderProfileEndpoint + "/" + "{" + profileIDPathParam + "}"
	signPresentationEndpoint = "/" + "{" + profileIDPathParam + "}" + "/prove/presentations"

	invalidRequestErrMsg = "Invalid request"
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

// New returns CreateCredential instance
func New(config *Config) (*Operation, error) {
	p, err := vcprofile.New(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		profileStore: p,
		commonDID: commondid.New(&commondid.Config{VDRI: config.VDRI, KeyManager: config.KeyManager,
			Domain: config.Domain, TLSConfig: config.TLSConfig}),
		crypto: crypto.New(config.KeyManager, config.Crypto, config.VDRI),
	}

	return svc, nil
}

// Config defines configuration for vcs operations
type Config struct {
	StoreProvider storage.Provider
	KeyManager    keyManager
	VDRI          vdriapi.Registry
	Domain        string
	TLSConfig     *tls.Config
	Crypto        ariescrypto.Crypto
}

type keyManager interface {
	kms.KeyManager
}

// Operation defines handlers for Edge service
type Operation struct {
	commonDID    commonDID
	profileStore *vcprofile.Profile
	crypto       *crypto.Crypto
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		// holder profile
		support.NewHTTPHandler(holderProfileEndpoint, http.MethodPost, o.createHolderProfileHandler),
		support.NewHTTPHandler(getHolderProfileEndpoint, http.MethodGet, o.getHolderProfileHandler),
		support.NewHTTPHandler(signPresentationEndpoint, http.MethodPost, o.signPresentationHandler),
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
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	if err := validateHolderProfileRequest(request); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	profile, err := o.profileStore.GetHolderProfile(request.Name)
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	if profile != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("profile %s already exists", profile.Name))

		return
	}

	profile, err = o.createHolderProfile(request)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	err = o.profileStore.SaveHolderProfile(profile)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, profile)
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
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, profile)
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
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid holder profile - id=%s: err=%s",
			profileID, err.Error()))

		return
	}

	// get the request
	presReq := SignPresentationRequest{}

	err = json.NewDecoder(req.Body).Decode(&presReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	presentation, err := verifiable.ParsePresentation(presReq.Presentation,
		verifiable.WithDisabledPresentationProofCheck())
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	// update holder
	updateHolder(presentation, profile)

	// sign presentation
	signedVP, err := o.crypto.SignPresentation(profile, presentation, getPresentationSigningOpts(presReq.Opts)...)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign presentation:"+
			" %s", err.Error()))

		return
	}

	rw.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(rw, signedVP)
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

func (o *Operation) createHolderProfile(pr *HolderProfileRequest) (*vcprofile.HolderProfile, error) {
	var didID, publicKeyID string

	didID, publicKeyID, err := o.commonDID.CreateDID(pr.DIDKeyType, pr.SignatureType, pr.DID,
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

func validateHolderProfileRequest(pr *HolderProfileRequest) error {
	if pr.Name == "" {
		return fmt.Errorf("missing profile name")
	}

	return nil
}
