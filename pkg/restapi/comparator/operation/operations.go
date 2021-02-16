/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

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

	"github.com/trustbloc/edge-service/pkg/client/csh"
	vaultclient "github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
	commhttp "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"
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
)

type cshClient interface {
	CreateProfile(controller string) (*openapi.Profile, error)
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

	op := &Operation{vdr: cfg.VDR, keyManager: cfg.KeyManager, tlsConfig: cfg.TLSConfig, didMethod: cfg.DIDMethod,
		store: store, cshClient: csh.New(cfg.CSHBaseURL, csh.WithTLSConfig(cfg.TLSConfig)),
		vaultClient: vaultclient.New(cfg.VaultBaseURL, vaultclient.WithTLSConfig(cfg.TLSConfig))}

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
		support.NewHTTPHandler(getConfigPath, http.MethodPost, o.GetConfig),
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
	w.WriteHeader(http.StatusCreated)
	commhttp.WriteResponse(w, Authorization{ID: "fakeID", RequestingParty: "fakeRP", AuthToken: "fakeZCAP"})
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
func (o *Operation) Compare(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	commhttp.WriteResponse(w, Comparison{Result: true})
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
			w.WriteHeader(http.StatusNotFound)
			return
		}

		commhttp.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())

		return
	}

	w.WriteHeader(http.StatusOK)
	commhttp.WriteResponse(w, cc)
}

func (o *Operation) getConfig() (*ComparatorConfig, error) {
	bytes, err := o.store.Get(configKeyDB)
	if err != nil {
		return nil, err
	}

	cc := ComparatorConfig{}
	if err := json.Unmarshal(bytes, &cc); err != nil {
		return nil, err
	}

	return &cc, nil
}

func (o *Operation) createConfig() error {
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

	configBytes, err := json.Marshal(ComparatorConfig{DID: docResolution.DIDDocument.ID, Keys: keys})
	if err != nil {
		return err
	}

	cshProfile, err := o.cshClient.CreateProfile(docResolution.DIDDocument.ID)
	if err != nil {
		return err
	}

	cshConfigBytes, err := json.Marshal(cshProfile)
	if err != nil {
		return err
	}

	if err := o.store.Put(cshConfigKeyDB, cshConfigBytes); err != nil {
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
