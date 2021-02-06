/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/trustbloc/edge-service/pkg/client/vault"
	edv "github.com/trustbloc/edv/pkg/client"
	"net/http"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	remotecrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	remotekms "github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi/models"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
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
)

var logger = log.New("confidential-storage-hub")

// Operation defines handlers for vault service.
type Operation struct {
	storage *struct {
		profiles storage.Store
		zcaps    storage.Store
	}
	aries      *AriesConfig
	httpClient *http.Client
	edvClient  func(string, ...edv.Option) vault.ConfidentialStorageDocReader
}

// Config defines configuration for vault operations.
type Config struct {
	StoreProvider storage.Provider
	Aries         *AriesConfig
	HTTPClient    *http.Client
	EDVClient     func(string, ...edv.Option) vault.ConfidentialStorageDocReader
}

// AriesConfig holds all configurations for aries-framework-go dependencies.
type AriesConfig struct {
	KMS       kms.KeyManager
	Crypto    crypto.Crypto
	WebKMS    func(string, *http.Client, ...remotekms.Opt) *remotekms.RemoteKMS
	WebCrypto func(string, *http.Client, ...remotekms.Opt) *remotecrypto.RemoteCrypto
}

// New returns operation instance.
func New(cfg *Config) (*Operation, error) {
	ops := &Operation{
		aries:      cfg.Aries,
		httpClient: cfg.HTTPClient,
		edvClient:  cfg.EDVClient,
	}

	var err error

	ops.storage, err = initStores(cfg.StoreProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to init store: %w", err)
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
		support.NewHTTPHandler(extractPath, http.MethodGet, o.Extract),
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
//   default: Error
func (o *Operation) CreateProfile(w http.ResponseWriter, r *http.Request) {
	logger.Infof("handling request")

	profile := &models.Profile{}

	err := json.NewDecoder(r.Body).Decode(profile)
	if err != nil {
		respondErrorf(w, http.StatusBadRequest, "bad request: %s", err.Error())

		return
	}

	if profile.Controller == "" {
		respondErrorf(w, http.StatusBadRequest, "missing controller")

		return
	}

	profile.ID = fmt.Sprintf("/hubstore/profiles/%s", uuid.New().String())

	zcap, err := o.newProfileZCAP(profile.ID, profile.Controller)
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

	profile.Zcap, err = gzipThenBase64URLEncode(zcap)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to compress zcap: %s", err.Error())

		return
	}

	// TODO specify full path for location
	headers := map[string]string{
		"Location":     profile.ID,
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
//   default: Error
func (o *Operation) CreateQuery(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusCreated)
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
//   default: Error
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
//   default: Error
func (o *Operation) Compare(w http.ResponseWriter, r *http.Request) {
	logger.Infof("handling request")

	request := &models.ComparisonRequest{}

	err := json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		respondErrorf(w, http.StatusBadRequest, "invalid request: %s", err.Error())

		return
	}

	switch op := request.Op().(type) {
	case *models.EqOp:
		o.handleEqOp(w, op)
	default:
		respondErrorf(w, http.StatusBadRequest, "invalid operation: %s", request.Op().Type())
	}

	logger.Infof("successfully handled request")
}

// Extract swagger:route GET /hubstore/extract extractionReq
//
// Extracts the contents of a document.
//
// Produces:
//   - application/json
// Responses:
//   200: extractionResp
//   500: Error
func (o *Operation) Extract(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// TODO add support for caveats in zcap: https://github.com/trustbloc/edge-core/issues/134
// TODO make supported crypto curves configurable: https://github.com/trustbloc/edge-service/issues/577
func (o *Operation) newProfileZCAP(profileID, controller string) (*zcapld.Capability, error) {
	signer, err := signature.NewCryptoSigner(o.aries.Crypto, o.aries.KMS, kms.ED25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new signer: %w", err)
	}

	return zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: didKeyURL(signer.PublicKeyBytes()),
		},
		zcapld.WithInvocationTarget(profileID, "urn:confidentialstoragehub:profile"),
		zcapld.WithID(profileID),
		zcapld.WithAllowedActions(allActions()...),
		zcapld.WithController(controller),
		zcapld.WithInvoker(controller),
	)
}

func initStores(p storage.Provider) (*struct {
	profiles storage.Store
	zcaps    storage.Store
}, error) {
	var (
		err    error
		stores = &struct {
			profiles storage.Store
			zcaps    storage.Store
		}{}
	)

	stores.profiles, err = initStore(p, profileStore)
	if err != nil {
		return nil, fmt.Errorf("failed to init %s: %w", profileStore, err)
	}

	stores.zcaps, err = initStore(p, zcapStore)
	if err != nil {
		return nil, fmt.Errorf("failed to init %s: %w", zcapStore, err)
	}

	return stores, nil
}

func initStore(p storage.Provider, name string) (storage.Store, error) {
	err := p.CreateStore(name)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, fmt.Errorf("failed to create profile store %s: %w", name, err)
	}

	return p.OpenStore(name)
}

func didKeyURL(pubKeyBytes []byte) string {
	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}

func respond(w http.ResponseWriter, statusCode int, headers map[string]string, payload interface{}) {
	w.WriteHeader(statusCode)

	for k, v := range headers {
		w.Header().Add(k, v)
	}

	err := json.NewEncoder(w).Encode(payload)
	if err != nil {
		logger.Errorf("failed to write response: %s", err.Error())
	}
}

func respondErrorf(w http.ResponseWriter, statusCode int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)

	logger.Errorf(msg)
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(&model.ErrorResponse{
		Message: msg,
	})
	if err != nil {
		logger.Errorf("failed to write error response: %s", err.Error())
	}
}

func gzipThenBase64URLEncode(msg interface{}) (string, error) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal msg: %w", err)
	}

	compressed := bytes.NewBuffer(nil)

	w := gzip.NewWriter(compressed)

	_, err = w.Write(raw)
	if err != nil {
		return "", fmt.Errorf("failed to compress msg: %w", err)
	}

	err = w.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return base64.URLEncoding.EncodeToString(compressed.Bytes()), nil
}

func save(s storage.Store, k string, v interface{}) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return s.Put(k, raw)
}
