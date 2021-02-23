/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesjoes "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/square/go-jose/v3"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edge-service/pkg/client/csh/client"
	"github.com/trustbloc/edge-service/pkg/client/csh/client/operations"
	cshclientmodels "github.com/trustbloc/edge-service/pkg/client/csh/models"
	vaultclient "github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/models"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

const (
	createAuthzPath = "/authorizations"
	comparePath     = "/compare"
	extractPath     = "/extract"
	getConfigPath   = "/config"
)

const (
	configKeyDB    = "config"
	cshConfigKeyDB = "csh_config"
	storeName      = "comparator"
	requestTimeout = 5 * time.Second
)

type cshClient interface {
	PostCompare(params *operations.PostCompareParams,
		opts ...operations.ClientOption) (*operations.PostCompareOK, error)

	PostHubstoreProfiles(params *operations.PostHubstoreProfilesParams,
		opts ...operations.ClientOption) (*operations.PostHubstoreProfilesCreated, error)
}

type vaultClient interface {
	GetDocMetaData(vaultID, docID string) (*vault.DocumentMetadata, error)
}

var logger = log.New("comparator-ops")

// Operation defines handlers for comparator service.
type Operation struct {
	vdr         vdr.Registry
	keyManager  kms.KeyManager
	tlsConfig   *tls.Config
	didMethod   string
	store       storage.Store
	cshClient   cshClient
	vaultClient vaultClient
}

// Config defines configuration for comparator operations.
type Config struct {
	VDR           vdr.Registry
	KeyManager    kms.KeyManager
	TLSConfig     *tls.Config
	DIDMethod     string
	StoreProvider storage.Provider
	CSHBaseURL    string
	VaultBaseURL  string
}

// New returns operation instance.
func New(cfg *Config) (*Operation, error) {
	store, err := cfg.StoreProvider.OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: cfg.TLSConfig,
		},
	}

	cshURL := strings.Split(cfg.CSHBaseURL, "://")

	transport := httptransport.NewWithClient(
		cshURL[1],
		client.DefaultBasePath,
		[]string{cshURL[0]},
		httpClient,
	)

	op := &Operation{
		vdr: cfg.VDR, keyManager: cfg.KeyManager, tlsConfig: cfg.TLSConfig, didMethod: cfg.DIDMethod,
		store: store, cshClient: client.New(transport, strfmt.Default).Operations,
		vaultClient: vaultclient.New(cfg.VaultBaseURL, vaultclient.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: cfg.TLSConfig,
			},
		})),
	}

	if _, err := op.getConfig(); err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			if errCreate := op.createConfig(); errCreate != nil {
				return nil, errCreate
			}

			logger.Infof("comparator config is created")

			return op, nil
		}

		return nil, err
	}

	logger.Infof("comparator config already created")

	return op, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{
		support.NewHTTPHandler(createAuthzPath, http.MethodPost, o.CreateAuthorization),
		support.NewHTTPHandler(comparePath, http.MethodPost, o.Compare),
		support.NewHTTPHandler(extractPath, http.MethodPost, o.Extract),
		support.NewHTTPHandler(getConfigPath, http.MethodGet, o.GetConfig),
	}
}

// CreateAuthorization swagger:route POST /authorizations createAuthzReq
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
	rp := "fakeRP"
	authToken := "fakeZCAP"

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respond(w, http.StatusOK, headers, models.Authorization{ID: "fakeID", RequestingParty: &rp, AuthToken: &authToken})
}

// Compare swagger:route POST /compare compareReq
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
	request := &models.Comparison{}

	err := json.NewDecoder(r.Body).Decode(request)
	if err != nil {
		respondErrorf(w, http.StatusBadRequest, "bad request: %s", err.Error())

		return
	}

	switch t := request.Op().(type) {
	case *models.EqOp:
		o.HandleEqOp(w, t)
	default:
		respondErrorf(w, http.StatusNotImplemented, "operator not yet implemented: %s", request.Op().Type())
	}
}

// Extract swagger:route POST /extract extractReq
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

// GetConfig swagger:route GET /config configReq
//
// Get config.
//
// Produces:
//   - application/json
// Responses:
//   200: configResp
//   500: Error
func (o *Operation) GetConfig(w http.ResponseWriter, _ *http.Request) {
	cc, err := o.getConfig()
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			respond(w, http.StatusNotFound, nil, nil)

			return
		}

		respondErrorf(w, http.StatusInternalServerError, err.Error())

		return
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respond(w, http.StatusOK, headers, cc)
}

func (o *Operation) getConfig() (*models.Config, error) {
	b, err := o.store.Get(configKeyDB)
	if err != nil {
		return nil, err
	}

	cc := models.Config{}
	if err := json.Unmarshal(b, &cc); err != nil {
		return nil, err
	}

	return &cc, nil
}

func (o *Operation) createConfig() error { //nolint: funlen,gocyclo
	// create did
	didDoc, keys, err := o.newPublicKeys()
	if err != nil {
		return fmt.Errorf("failed to create public keys : %w", err)
	}

	recoverKey, err := o.newKey()
	if err != nil {
		return fmt.Errorf("failed to create recover key : %w", err)
	}

	updateKey, err := o.newKey()
	if err != nil {
		return fmt.Errorf("failed to update recover key : %w", err)
	}

	docResolution, err := o.vdr.Create(o.didMethod, didDoc,
		vdr.WithOption(trustbloc.RecoveryPublicKeyOpt, recoverKey),
		vdr.WithOption(trustbloc.UpdatePublicKeyOpt, updateKey),
	)
	if err != nil {
		return fmt.Errorf("failed to create DID : %w", err)
	}

	request := &cshclientmodels.Profile{}
	request.Controller = &docResolution.DIDDocument.ID

	cshProfile, err := o.cshClient.PostHubstoreProfiles(
		operations.NewPostHubstoreProfilesParams().WithTimeout(requestTimeout).WithRequest(request))
	if err != nil {
		return err
	}

	// TODO need to find better way to get csh DID
	cshZCAP, err := parseCompressedZCAP(cshProfile.Payload.Zcap)
	if err != nil {
		return fmt.Errorf("failed to parse CHS profile zcap: %w", err)
	}

	cshConfigBytes, err := cshProfile.Payload.MarshalBinary()
	if err != nil {
		return err
	}

	if errPut := o.store.Put(cshConfigKeyDB, cshConfigBytes); errPut != nil {
		return errPut
	}

	authKeyURL, ok := cshZCAP.Proof[0]["verificationMethod"].(string)
	if !ok {
		return fmt.Errorf("failed to cast verificationMethod from cshZCAP")
	}

	configBytes, err := json.Marshal(models.Config{Did: &docResolution.DIDDocument.ID, Key: keys,
		AuthKeyURL: authKeyURL})
	if err != nil {
		return err
	}

	// store config
	return o.store.Put(configKeyDB, configBytes)
}

func (o *Operation) newPublicKeys() (*did.Doc, []json.RawMessage, error) {
	didDoc := &did.Doc{}

	m := make([]json.RawMessage, 0)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	keyID := uuid.New().String()

	jwkBytes, err := jose.JSONWebKey{KeyID: keyID, Key: privateKey}.MarshalJSON()
	if err != nil {
		return nil, nil, err
	}

	m = append(m, jwkBytes)

	jwk, err := ariesjoes.JWKFromPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	vm, err := did.NewVerificationMethodFromJWK(keyID, doc.JWSVerificationKey2020, "", jwk)
	if err != nil {
		return nil, nil, err
	}

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	return didDoc, m, nil
}

func (o *Operation) newKey() (crypto.PublicKey, error) {
	_, bits, err := o.keyManager.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create key : %w", err)
	}

	return ed25519.PublicKey(bits), nil
}

func respond(w http.ResponseWriter, statusCode int, headers map[string]string, payload interface{}) {
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

	w.Header().Add("Content-Type", "application/json")

	logger.Errorf(msg)
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(&model.ErrorResponse{
		Message: msg,
	})
	if err != nil {
		logger.Errorf("failed to write error response: %s", err.Error())
	}
}

func parseCompressedZCAP(compressed string) (*zcapld.Capability, error) {
	uncompressed, err := base64URLDecodeThenGunzip(compressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress zcap: %w", err)
	}

	zcap, err := zcapld.ParseCapability(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse zcap: %w", err)
	}

	return zcap, nil
}

func base64URLDecodeThenGunzip(encoded string) ([]byte, error) {
	compressed, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url-decode string: %w", err)
	}

	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("failed to open a new gzip reader: %w", err)
	}

	inflated := bytes.NewBuffer(nil)

	_, err = inflated.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("failed to gunzip string: %w", err)
	}

	return inflated.Bytes(), nil
}
