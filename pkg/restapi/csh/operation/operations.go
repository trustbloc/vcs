/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	did2 "github.com/trustbloc/edge-service/pkg/did"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
	zcapld2 "github.com/trustbloc/edge-service/pkg/restapi/csh/operation/zcapld"
)

const (
	operationID       = "/hubstore/profiles"
	createProfilePath = operationID
	createQueryPath   = operationID + "/{profileID}/queries"
	createAuthzPath   = operationID + "/{profileID}/authorizations"

	comparePath = "/compare"
	extractPath = "/extract"
)

const (
	profileStore = "profile"
	zcapStore    = "zcap"
	queryStore   = "queries"
	configStore  = "config"

	identityKey = "config"
)

var logger = log.New("confidential-storage-hub")

// Operation defines handlers for vault service.
type Operation struct {
	storage *struct {
		profiles storage.Store
		zcaps    storage.Store
		queries  storage.Store
		config   storage.Store
	}
	aries      *AriesConfig
	httpClient *http.Client
	edvClient  func(string, ...edv.Option) vault.ConfidentialStorageDocReader
	baseURL    string
}

// Config defines configuration for vault operations.
type Config struct {
	StoreProvider storage.Provider
	Aries         *AriesConfig
	HTTPClient    *http.Client
	EDVClient     func(string, ...edv.Option) vault.ConfidentialStorageDocReader
	BaseURL       string
}

// AriesConfig holds all configurations for aries-framework-go dependencies.
type AriesConfig struct {
	KMS              kms.KeyManager
	Crypto           crypto.Crypto
	WebKMS           func(string, webkms.HTTPClient, ...webkms.Opt) kms.KeyManager
	WebCrypto        func(string, webcrypto.HTTPClient, ...webkms.Opt) crypto.Crypto
	DIDResolvers     []zcapld2.DIDResolver
	PublicDIDCreator func(kms.KeyManager) (*did.DocResolution, error)
}

// New returns operation instance.
func New(cfg *Config) (*Operation, error) {
	ops := &Operation{
		aries:      cfg.Aries,
		httpClient: cfg.HTTPClient,
		edvClient:  cfg.EDVClient,
		baseURL:    cfg.BaseURL,
	}

	err := ops.configure(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to configure operations: %w", err)
	}

	return ops, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{
		support.NewHTTPHandler(createProfilePath, http.MethodPost, o.CreateProfile),
		support.NewHTTPHandler(createQueryPath, http.MethodPost, o.CreateQuery),
		support.NewHTTPHandler(createAuthzPath, http.MethodPost, o.CreateAuthorization),
		support.NewHTTPHandler(comparePath, http.MethodPost, o.Compare),
		support.NewHTTPHandler(extractPath, http.MethodPost, o.Extract),
	}
}

// CreateProfile swagger:route POST /hubstore/profiles createProfileReq
//
// Creates a Profile.
//
// Produces:
//   - application/json
// Responses:
//   201: createProfileResp
//   500: Error
func (o *Operation) CreateProfile(w http.ResponseWriter, r *http.Request) {
	logger.Infof("handling request")

	profile := &openapi.Profile{}

	err := json.NewDecoder(r.Body).Decode(profile)
	if err != nil {
		respondErrorf(w, http.StatusBadRequest, "bad request: %s", err.Error())

		return
	}

	if profile.Controller == nil {
		respondErrorf(w, http.StatusBadRequest, "missing controller")

		return
	}

	profile.ID = uuid.New().URN()

	zcap, err := o.newProfileZCAP(profile.ID, *profile.Controller)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to create zcap: %s", err.Error())

		return
	}

	err = save(o.storage.zcaps, profile.ID, zcap)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to store zcap: %s", err.Error())

		return
	}

	err = save(o.storage.profiles, profile.ID, profile)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to store profile: %s", err.Error())

		return
	}

	profile.Zcap, err = zcapld.CompressZCAP(zcap)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to compress zcap: %s", err.Error())

		return
	}

	// TODO specify full path for location
	headers := map[string]string{
		"Location":     fmt.Sprintf("%s/hubstore/profiles/%s", o.baseURL, profile.ID),
		"Content-Type": "application/json",
	}

	respond(w, http.StatusCreated, headers, profile)
	logger.Infof("finished handling request")
}

// CreateQuery swagger:route POST /hubstore/profiles/{profileID}/queries createQueryReq
//
// Creates a Query.
//
// Consumes:
//   - application/json
// Produces:
//   - application/json
// Responses:
//   201: createQueryResp
//   400: Error
//   403: Error
//   500: Error
func (o *Operation) CreateQuery(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling request")

	query, err := openapi.UnmarshalQuery(r.Body, runtime.JSONConsumer())
	if err != nil {
		respondErrorf(w, http.StatusBadRequest, "bad request: %s", err.Error())

		return
	}

	switch query.(type) {
	case *openapi.DocQuery: // allow DocQuery
	case *openapi.RefQuery:
		respondErrorf(w, http.StatusBadRequest, "query type not allowed: %s", query.Type())

		return
	default:
		respondErrorf(w, http.StatusNotImplemented, "unsupported query type: %s", query.Type())

		return
	}

	profileID := mux.Vars(r)["profileID"]

	raw, err := json.Marshal(query)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError,
			"failed to marshal query (this shouldn't have happened): %s", err.Error())

		return
	}

	entity := &Query{
		ID:        uuid.New().String(),
		ProfileID: profileID,
		Spec:      raw,
	}

	err = save(o.storage.queries, entity.ID, entity)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to persist query: %s", err.Error())
	}

	headers := map[string]string{
		"Location": fmt.Sprintf("%s/hubstore/profiles/%s/queries/%s", o.baseURL, profileID, entity.ID),
	}

	respond(w, http.StatusCreated, headers, nil)
	logger.Debugf("handled request")
}

// CreateAuthorization swagger:route POST /hubstore/profiles/{profileID}/authorizations createAuthorizationReq
//
// Creates an Authorization.
//
// Consumes:
//   - application/json
// Produces:
//   - application/json
// Responses:
//   201: createAuthorizationResp
//   403: Error
//   500: Error
func (o *Operation) CreateAuthorization(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusCreated)
}

// Compare swagger:route POST /hubstore/compare comparisonReq
//
// Performs a comparison.
//
// Consumes:
//   - application/json
// Produces:
//   - application/json
// Responses:
//   200: comparisonResp
//   500: Error
func (o *Operation) Compare(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling request")

	request := &openapi.ComparisonRequest{}

	err := json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		respondErrorf(w, http.StatusBadRequest, "bad request: %s", err.Error())

		return
	}

	switch t := request.Op().(type) {
	case *openapi.EqOp:
		o.HandleEqOp(w, t)
	default:
		respondErrorf(w, http.StatusNotImplemented, "operator not yet implemented: %s", request.Op().Type())
	}

	logger.Debugf("handled request")
}

// Extract swagger:route POST /hubstore/extract extractionReq
//
// Extracts the contents of a document.
//
// Consumes:
//   - application/json
// Produces:
//   - application/json
// Responses:
//   200: extractionResp
//   400: Error
//   500: Error
func (o *Operation) Extract(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling request")

	queries, err := openapi.UnmarshalQuerySlice(r.Body, runtime.JSONConsumer())
	if err != nil {
		respondErrorf(w, http.StatusBadRequest, "bad request: %s", err.Error())

		return
	}

	var extractions openapi.ExtractionResponse

	for i := range queries {
		query := queries[i]

		var doc interface{}

		switch q := query.(type) {
		case *openapi.DocQuery:
			var err error

			doc, err = o.fetchDocument(q)
			if err != nil {
				respondErrorf(w, http.StatusInternalServerError,
					"failed to fetch document for DocQuery: %s", err.Error())

				return
			}
		case *openapi.RefQuery:
			var proceed bool

			doc, proceed = o.resolveRefQuery(w, q)
			if !proceed {
				return
			}
		}

		extractions = append(extractions, &openapi.ExtractionResponseItems0{
			ID:       query.ID(),
			Document: doc,
		})
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respond(w, http.StatusOK, headers, extractions)
	logger.Debugf("handled request")
}

// TODO add support for caveats in zcap: https://github.com/trustbloc/edge-core/issues/134
// TODO make supported crypto curves configurable: https://github.com/trustbloc/edge-service/issues/577
func (o *Operation) newProfileZCAP(profileID, controller string) (*zcapld.Capability, error) {
	identity, err := o.identityConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load identity: %w", err)
	}

	handle, err := o.aries.KMS.Get(identity.DelegationKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch delegation key id [%s]: %w", identity.DelegationKeyID, err)
	}

	return zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite: jsonwebsignature2020.New(suite.WithSigner(&signer{
				c:  o.aries.Crypto,
				kh: handle,
			})),
			SuiteType:          "JsonWebSignature2020", // TODO this constant should be exposed in the framework
			VerificationMethod: identity.DelegationKeyURL,
		},
		zcapld.WithInvocationTarget(profileID, "urn:confidentialstoragehub:profile"),
		zcapld.WithID(profileID),
		zcapld.WithAllowedActions(allActions()...),
		zcapld.WithController(controller),
		zcapld.WithInvoker(controller),
	)
}

func (o *Operation) configure(cfg *Config) error {
	var err error

	o.storage, err = initStores(cfg.StoreProvider)
	if err != nil {
		return fmt.Errorf("failed to init store: %w", err)
	}

	identity, err := o.identityConfig()
	if errors.Is(err, storage.ErrDataNotFound) {
		identity, err = o.newIdentity()
		if err != nil {
			return fmt.Errorf("failed to create new identity: %w", err)
		}

		logger.Infof("created new identity")

		return save(o.storage.config, identityKey, identity)
	}

	logger.Infof("configured with identity: %+v", identity)

	return err
}

// TODO - control concurrency in a cluster
func (o *Operation) identityConfig() (*Identity, error) {
	raw, err := o.storage.config.Get(identityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup Identity from storage: %w", err)
	}

	config := &Identity{}

	return config, json.Unmarshal(raw, config)
}

func (o *Operation) newIdentity() (*Identity, error) {
	resolution, err := o.aries.PublicDIDCreator(o.aries.KMS)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity did: %w", err)
	}

	logger.Infof("new identity did: %s", resolution.DIDDocument.ID)

	verificationMethods, err := did2.VerificationMethods(
		resolution.DIDDocument,
		did.Authentication, did.CapabilityDelegation, did.CapabilityInvocation,
	)
	if err != nil {
		return nil, fmt.Errorf("public DID %s is missing some verification methods: %w", resolution.DIDDocument.ID, err)
	}

	authentication := verificationMethods[0]
	capabilityDelegation := verificationMethods[1]
	capabilityInvocation := verificationMethods[2]

	// TODO - note that at present the did-core spec does not mandate for these IDs to have fragments. I
	//  believe this is a mistake - see https://github.com/w3c/did-core/issues/708.
	keyIDs, err := did2.Fragments(authentication.ID, capabilityDelegation.ID, capabilityInvocation.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to determine identity keyIDs: %w", err)
	}

	authKeyID := keyIDs[0]
	delegationKeyID := keyIDs[1]
	invocationKeyID := keyIDs[2]

	return &Identity{
		DIDDoc:           resolution.DIDDocument,
		AuthKeyID:        authKeyID,
		DelegationKeyID:  delegationKeyID,
		DelegationKeyURL: capabilityDelegation.ID,
		InvocationKeyID:  invocationKeyID,
	}, nil
}

func initStores(p storage.Provider) (*struct {
	profiles storage.Store
	zcaps    storage.Store
	queries  storage.Store
	config   storage.Store
}, error) {
	stores := &struct {
		profiles storage.Store
		zcaps    storage.Store
		queries  storage.Store
		config   storage.Store
	}{}

	s := [4]storage.Store{}

	for i, name := range []string{profileStore, zcapStore, queryStore, configStore} {
		var err error

		s[i], err = initStore(p, name)
		if err != nil {
			return nil, fmt.Errorf("failed to init %s: %w", name, err)
		}
	}

	stores.profiles = s[0]
	stores.zcaps = s[1]
	stores.queries = s[2]
	stores.config = s[3]

	return stores, nil
}

func initStore(p storage.Provider, name string) (storage.Store, error) {
	return p.OpenStore(name)
}

func respond(w http.ResponseWriter, statusCode int, headers map[string]string, payload interface{}) {
	// godocs:
	// Changing the header map after a call to WriteHeader (or Write) has no effect unless the modified headers
	// are trailers.
	for k, v := range headers {
		w.Header().Add(k, v)
	}

	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(payload)
	if err != nil {
		logger.Errorf("failed to write response: %s", err.Error())
	}
}

func respondErrorf(w http.ResponseWriter, statusCode int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)

	logger.Errorf(msg)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(&openapi.Error{
		ErrMessage: msg,
	})
	if err != nil {
		logger.Errorf("failed to write error response: %s", err.Error())
	}
}

func save(s storage.Store, k string, v interface{}) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return s.Put(k, raw)
}

type signer struct {
	c  crypto.Crypto
	kh interface{}
}

func (s *signer) Sign(data []byte) ([]byte, error) {
	return s.c.Sign(data, s.kh)
}
