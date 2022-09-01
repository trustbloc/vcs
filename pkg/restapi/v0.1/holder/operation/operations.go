/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	commondid "github.com/trustbloc/vcs/pkg/restapi/v0.1/internal/common/did"
	commhttp "github.com/trustbloc/vcs/pkg/restapi/v0.1/internal/common/http"

	vcsstorage "github.com/trustbloc/vcs/pkg/storage"

	"github.com/gorilla/mux"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/internal/common/support"
)

const (
	profileIDPathParam = "profileID"

	holderProfileEndpoint       = "/holder/profile"
	getHolderProfileEndpoint    = holderProfileEndpoint + "/" + "{" + profileIDPathParam + "}"
	deleteHolderProfileEndpoint = holderProfileEndpoint + "/" + "{" + profileIDPathParam + "}"
	signPresentationEndpoint    = "/" + "{" + profileIDPathParam + "}" + "/prove/presentations"
	deriveCredentialsEndpoint   = "/" + "{" + profileIDPathParam + "}" + "/credentials/derive"

	invalidRequestErrMsg = "Invalid request"
)

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type commonDID interface {
	CreateDID(keyType, signatureType, did, privateKey, keyID string) (string, string, error)
}

// New returns CreateCredential instance.
func New(config *Config) (*Operation, error) {
	profileStore, err := config.StoreProvider.OpenHolderProfileStore()
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		vdr:          config.VDRI,
		profileStore: profileStore,
		commonDID: commondid.New(&commondid.Config{
			VDRI: config.VDRI, KeyManager: config.KeyManager,
			Domain: config.Domain, TLSConfig: config.TLSConfig,
			DIDAnchorOrigin: config.DIDAnchorOrigin,
		}),
		crypto:         crypto.New(config.KeyManager, config.Crypto, config.VDRI, config.DocumentLoader),
		documentLoader: config.DocumentLoader,
	}

	return svc, nil
}

// Config defines configuration for vcs operations.
type Config struct {
	StoreProvider   vcsstorage.Provider
	KeyManager      keyManager
	VDRI            vdrapi.Registry
	Domain          string
	TLSConfig       *tls.Config
	Crypto          ariescrypto.Crypto
	DIDAnchorOrigin string
	DocumentLoader  ld.DocumentLoader
}

type keyManager interface {
	kms.KeyManager
}

// Operation defines handlers for holder service.
type Operation struct {
	commonDID      commonDID
	profileStore   vcsstorage.HolderProfileStore
	crypto         *crypto.Crypto
	vdr            vdrapi.Registry
	documentLoader ld.DocumentLoader
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		// holder profile
		support.NewHTTPHandler(holderProfileEndpoint, http.MethodPost, o.createHolderProfileHandler),
		support.NewHTTPHandler(getHolderProfileEndpoint, http.MethodGet, o.getHolderProfileHandler),
		support.NewHTTPHandler(deleteHolderProfileEndpoint, http.MethodDelete, o.deleteHolderProfileHandler),
		support.NewHTTPHandler(signPresentationEndpoint, http.MethodPost, o.signPresentationHandler),
		support.NewHTTPHandler(deriveCredentialsEndpoint, http.MethodPost, o.deriveCredentialsHandler),
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

	_, err := o.profileStore.Get(request.Name)
	if err == nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("profile %s already exists", request.Name))

		return
	} else if !errors.Is(err, ariesstorage.ErrDataNotFound) {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	profile, err := o.createHolderProfile(request)
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

// RetrieveHolderProfile swagger:route GET /holder/profile/{id} holder retrieveHolderProfileReq
//
// Retrieves holder profile.
//
// Responses:
//    default: genericError
//        200: holderProfileRes
func (o *Operation) getHolderProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[profileIDPathParam]

	profile, err := o.profileStore.Get(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, http.StatusOK, profile)
}

// DeleteHolderProfile swagger:route DELETE /holder/profile/{id} holder deleteHolderProfileReq
//
// Deletes holder profile.
//
// Responses:
// 		default: genericError
//			200: emptyRes
func (o *Operation) deleteHolderProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[profileIDPathParam]

	err := o.profileStore.Delete(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, http.StatusOK, nil)
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

	profile, err := o.profileStore.Get(profileID)
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

	presentation, err := verifiable.ParsePresentation(presReq.Presentation, verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	// update holder
	updateHolder(presentation, &profile)

	// sign presentation
	signedVP, err := o.crypto.SignPresentation(&profile, presentation, getPresentationSigningOpts(presReq.Opts)...)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf("failed to sign presentation:"+
			" %s", err.Error()))

		return
	}

	commhttp.WriteResponse(rw, http.StatusCreated, signedVP)
}

// DeriveCredentials swagger:route POST /{id}/credentials/derive holder deriveCredentialReq
//
// derive Credentials.
//
// Responses:
//    default: genericError
//        201: deriveCredentialRes
func (o *Operation) deriveCredentialsHandler(rw http.ResponseWriter, req *http.Request) {
	// get the request
	deriveReq := DeriveCredentialRequest{}

	err := json.NewDecoder(req.Body).Decode(&deriveReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	if len(deriveReq.Credential) == 0 {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, "credential is mandatory")

		return
	}

	if len(deriveReq.Frame) == 0 {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, "frame is mandatory")

		return
	}

	credential, err := verifiable.ParseCredential(deriveReq.Credential,
		verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(o.vdr).PublicKeyFetcher()),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader),
	)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to parse credential: %s", err.Error()))

		return
	}

	nonceBytes, err := nonceFromDeriveRequestOpts(&deriveReq.Opts)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())
	}

	derived, err := credential.GenerateBBSSelectiveDisclosure(deriveReq.Frame, nonceBytes,
		verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(o.vdr).PublicKeyFetcher()),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader),
	)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to generate BBS selective disclosure: %s", err.Error()))

		return
	}

	vcBytes, err := derived.MarshalJSON()
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to matshal derived vc: %s", err.Error()))

		return
	}

	commhttp.WriteResponse(rw, http.StatusCreated, DeriveCredentialResponse{
		VerifiableCredential: vcBytes,
	})
}

func nonceFromDeriveRequestOpts(options *DeriveCredentialOptions) ([]byte, error) {
	const defaultNonceSize = 50

	// if nonce not provided generate one
	if options.Nonce == nil {
		nonceBytes := make([]byte, defaultNonceSize)

		_, err := rand.Read(nonceBytes)
		if err != nil {
			return nil, fmt.Errorf("generating random failed: %w", err)
		}

		return nonceBytes, nil
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(*options.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	return nonceBytes, nil
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
func updateHolder(presentation *verifiable.Presentation, profile *vcsstorage.HolderProfile) {
	if profile.OverwriteHolder || presentation.Holder == "" {
		presentation.Holder = profile.DID
	}
}

func (o *Operation) createHolderProfile(pr *HolderProfileRequest) (*vcsstorage.HolderProfile, error) {
	var didID, publicKeyID string

	didID, publicKeyID, err := o.commonDID.CreateDID(pr.DIDKeyType, pr.SignatureType, pr.DID,
		pr.DIDPrivateKey, pr.DIDKeyID)
	if err != nil {
		return nil, err
	}

	created := time.Now().UTC()

	return &vcsstorage.HolderProfile{
		DataProfile: vcsstorage.DataProfile{
			Name:                    pr.Name,
			Created:                 &created,
			DID:                     didID,
			SignatureType:           pr.SignatureType,
			SignatureRepresentation: pr.SignatureRepresentation,
			Creator:                 publicKeyID,
		},
		OverwriteHolder: pr.OverwriteHolder,
	}, nil
}

func validateHolderProfileRequest(pr *HolderProfileRequest) error {
	if pr.Name == "" {
		return fmt.Errorf("missing profile name")
	}

	return nil
}
