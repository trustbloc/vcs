/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	cshclientmodels "github.com/trustbloc/edge-service/pkg/client/csh/models"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/models"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

func Test_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			chs := newAgent(t)
			chsZCAP := newZCAP(t, chs, chs)
			p := cshclientmodels.Profile{Zcap: compress(t, marshal(t, chsZCAP))}
			b, err := p.MarshalBinary()
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		op, err := operation.New(&operation.Config{CSHBaseURL: serv.URL, StoreProvider: &mockstorage.MockStoreProvider{
			Store: s}, KeyManager: &mockkms.KeyManager{}, VDR: &vdr.MockVDRegistry{
			CreateFunc: func(s string, doc *did.Doc, option ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: &did.Doc{ID: "did:ex:123"}}, nil
			}}})
		require.NoError(t, err)
		require.NotNil(t, op)

		require.Equal(t, 4, len(op.GetRESTHandlers()))
	})

	t.Run("test failed to create profile from csh", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		_, err := operation.New(&operation.Config{CSHBaseURL: serv.URL, StoreProvider: &mockstorage.MockStoreProvider{
			Store: s}, KeyManager: &mockkms.KeyManager{}, VDR: &vdr.MockVDRegistry{
			CreateFunc: func(s string, doc *did.Doc, option ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: &did.Doc{ID: "did:ex:123"}}, nil
			}}})
		require.Error(t, err)
	})

	t.Run("test failed to create store", func(t *testing.T) {
		_, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf("failed to open store")}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})

	t.Run("test failed to export public key", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		_, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: s}, KeyManager: &mockkms.KeyManager{CrAndExportPubKeyErr: fmt.Errorf("failed to export")}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to export")
	})

	t.Run("test failed to get config", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.ErrGet = fmt.Errorf("failed to get config")
		_, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get config")
	})
}

func TestOperation_CreateAuthorization(t *testing.T) {
	t.Run("test bad request", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.CreateAuthorization(result, newReq(t,
			http.MethodPost,
			"/authorizations",
			nil,
		))

		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "bad request")
	})

	t.Run("test failed to get doc meta from vault server", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost", VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		auth := &models.Authorization{}
		docID := "docID11"
		vaultID := "vaultID11"
		auth.Scope = &models.Scope{DocID: &docID, VaultID: vaultID}
		op.CreateAuthorization(result, newReq(t,
			http.MethodPost,
			"/authorizations",
			auth,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to get doc meta")
	})

	t.Run("test failed to parse doc meta EncKeyURI from vault server", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "/test/test/test/test", EncKeyURI: "hyyp://ww !###whht"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost", VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		auth := &models.Authorization{}
		docID := "docID12"
		vaultID := "vaultID12"
		auth.Scope = &models.Scope{DocID: &docID, VaultID: vaultID}
		op.CreateAuthorization(result, newReq(t,
			http.MethodPost,
			"/authorizations",
			auth,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to parse enc key uri")
	})

	t.Run("test failed to parse doc meta URI from vault server", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "hyyp://ww !###whht"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost", VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		auth := &models.Authorization{}
		docID := "docID13"
		vaultID := "vaultID13"
		auth.Scope = &models.Scope{DocID: &docID, VaultID: vaultID}
		op.CreateAuthorization(result, newReq(t,
			http.MethodPost,
			"/authorizations",
			auth,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to parse doc uri")
	})

	t.Run("test error from create query csh", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "/test/test/test/test"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		cshServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: cshServ.URL, VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		auth := &models.Authorization{}
		docID := "docID14"
		vaultID := "vaultID14"
		auth.Scope = &models.Scope{DocID: &docID, VaultID: vaultID,
			AuthTokens: &models.ScopeAuthTokens{Kms: "kms", Edv: "edv"}}
		op.CreateAuthorization(result, newReq(t,
			http.MethodPost,
			"/authorizations",
			auth,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to create query")
	})

	t.Run("test failed to get csh zcap", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "/test/test/test/test"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		cshServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", "https://localhost:8080/queries")
			w.WriteHeader(http.StatusCreated)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: cshServ.URL, VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		rpDID := "did1"
		auth := &models.Authorization{RequestingParty: &rpDID}
		docID := "docID15"
		vaultID := "vaultID15"
		auth.Scope = &models.Scope{DocID: &docID, VaultID: vaultID,
			AuthTokens: &models.ScopeAuthTokens{Kms: "kms", Edv: "edv"}}
		op.CreateAuthorization(result, newReq(t,
			http.MethodPost,
			"/authorizations",
			auth,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to parse CHS profile zcap")
	})

	t.Run("test failed to get keys from config", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "/test/test/test/test"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		cshServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", "https://localhost:8080/queries")
			w.WriteHeader(http.StatusCreated)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)

		chs := newAgent(t)
		chsZCAP := newZCAP(t, chs, chs)
		p := cshclientmodels.Profile{Zcap: compress(t, marshal(t, chsZCAP))}
		chsProfileBytes, err := p.MarshalBinary()
		require.NoError(t, err)
		s.Store["csh_config"] = chsProfileBytes
		op, err := operation.New(&operation.Config{CSHBaseURL: cshServ.URL, VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		rpDID := "did2"
		auth := &models.Authorization{RequestingParty: &rpDID}
		docID := "docID16"
		vaultID := "vaultID16"
		auth.Scope = &models.Scope{DocID: &docID, VaultID: vaultID,
			AuthTokens: &models.ScopeAuthTokens{Kms: "kms", Edv: "edv"}}
		op.CreateAuthorization(result, newReq(t,
			http.MethodPost,
			"/authorizations",
			auth,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "key is not array")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "/test/test/test/test"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		cshServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", "https://localhost:8080/queries")
			w.WriteHeader(http.StatusCreated)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		didID := "did:ex:123"
		m := make([]json.RawMessage, 0)
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		keyID := uuid.New().String()
		jwkBytes, err := jose.JSONWebKey{KeyID: keyID, Key: privateKey}.MarshalJSON()
		require.NoError(t, err)
		m = append(m, jwkBytes)
		conf := models.Config{Did: &didID, Key: m}
		confBytes, err := conf.MarshalBinary()
		require.NoError(t, err)
		s.Store["config"] = confBytes
		chs := newAgent(t)
		chsZCAP := newZCAP(t, chs, chs)
		p := cshclientmodels.Profile{Zcap: compress(t, marshal(t, chsZCAP))}
		chsProfileBytes, err := p.MarshalBinary()
		require.NoError(t, err)
		s.Store["csh_config"] = chsProfileBytes
		op, err := operation.New(&operation.Config{CSHBaseURL: cshServ.URL, VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		rpDID := "did3"
		auth := &models.Authorization{RequestingParty: &rpDID}
		docID := "docID17"
		vaultID := "vaultID17"
		auth.Scope = &models.Scope{DocID: &docID, VaultID: vaultID,
			AuthTokens: &models.ScopeAuthTokens{Kms: "kms", Edv: "edv"}}
		auth.Scope.SetCaveats([]models.Caveat{&models.ExpiryCaveat{Duration: int64(200)}})
		op.CreateAuthorization(result, newReq(t,
			http.MethodPost,
			"/authorizations",
			auth,
		))

		require.Equal(t, http.StatusOK, result.Code)
		require.Contains(t, result.Body.String(), "authToken")
	})
}

func TestOperation_Compare(t *testing.T) {
	t.Run("test bad request", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.Compare(result, newReq(t,
			http.MethodPost,
			"/compare",
			nil,
		))

		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "bad request")
	})

	t.Run("test failed to get doc meta from vault server", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost", VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		cr := &models.Comparison{}
		eq := &models.EqOp{}
		query := make([]models.Query, 0)
		docID := "docID18"
		vaultID := "vaultID18"
		query = append(query, &models.DocQuery{DocID: &docID, VaultID: &vaultID})
		eq.SetArgs(query)
		cr.SetOp(eq)
		op.Compare(result, newReq(t,
			http.MethodPost,
			"/compare",
			cr,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to get doc meta")
	})

	t.Run("test error from compare csh", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "/test/test/test/test"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		cshServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: cshServ.URL, VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		cr := &models.Comparison{}
		eq := &models.EqOp{}
		query := make([]models.Query, 0)
		docID := "docID2"
		vaultID := "vaultID2"
		query = append(query, &models.DocQuery{DocID: &docID, VaultID: &vaultID,
			AuthTokens: &models.DocQueryAO1AuthTokens{Edv: "edvToken", Kms: "kmsToken"}})
		eq.SetArgs(query)
		cr.SetOp(eq)
		op.Compare(result, newReq(t,
			http.MethodPost,
			"/compare",
			cr,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to execute comparison")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "/test/test/test/test"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		cshServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			p := cshclientmodels.Comparison{Result: true}
			b, err := p.MarshalBinary()
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: cshServ.URL, VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		cr := &models.Comparison{}
		eq := &models.EqOp{}
		query := make([]models.Query, 0)
		docID := "docID3"
		vaultID := "vaultID3"
		query = append(query, &models.DocQuery{DocID: &docID, VaultID: &vaultID,
			AuthTokens: &models.DocQueryAO1AuthTokens{Edv: "edvToken", Kms: "kmsToken"}})
		eq.SetArgs(query)
		cr.SetOp(eq)
		op.Compare(result, newReq(t,
			http.MethodPost,
			"/compare",
			cr,
		))

		require.Equal(t, http.StatusOK, result.Code)
		require.Contains(t, result.Body.String(), "true")
	})
}

func TestOperation_Extract(t *testing.T) {
	t.Run("TODO - performs an extraction", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.Extract(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
	})
}

func TestOperation_GetConfig(t *testing.T) {
	t.Run("get config success", func(t *testing.T) {
		s := make(map[string][]byte)
		s["config"] = []byte(`{}`)
		s["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{Store: s}}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.GetConfig(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
		require.Contains(t, result.Body.String(), "did")
	})

	t.Run("get config not found", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: s}})
		delete(s.Store, "config")
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.GetConfig(result, nil)
		require.Equal(t, http.StatusNotFound, result.Code)
	})

	t.Run("get config error", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		s.Store["csh_config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: s}})
		s.ErrGet = fmt.Errorf("failed to get config")
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.GetConfig(result, nil)
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to get config")
	})
}

func newReq(t *testing.T, method, path string, payload interface{}) *http.Request { //nolint: unparam
	t.Helper()

	var body io.Reader

	if payload != nil {
		raw, err := json.Marshal(payload)
		require.NoError(t, err)

		body = bytes.NewReader(raw)
	}

	return httptest.NewRequest(method, path, body)
}

func newZCAP(t *testing.T, server, rp *context.Provider) *zcapld.Capability {
	t.Helper()

	_, pubKeyBytes, err := rp.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	invoker := didKeyURL(pubKeyBytes)

	signer, err := signature.NewCryptoSigner(server.Crypto(), server.KMS(), kms.ED25519Type)
	require.NoError(t, err)

	verificationMethod := didKeyURL(signer.PublicKeyBytes())

	zcap, err := zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: verificationMethod,
		},
		zcapld.WithID(uuid.New().URN()),
		zcapld.WithInvoker(invoker),
		zcapld.WithController(invoker),
		zcapld.WithInvocationTarget(
			fmt.Sprintf("https://kms.example.com/kms/keystores/%s", uuid.New().String()),
			"urn:confidentialstoragehub:profile",
		),
	)
	require.NoError(t, err)

	return zcap
}

func newAgent(t *testing.T) *context.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}

func didKeyURL(pubKeyBytes []byte) string {
	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}

func compress(t *testing.T, msg []byte) string {
	t.Helper()

	compressed := bytes.NewBuffer(nil)
	compressor := gzip.NewWriter(compressed)

	_, err := compressor.Write(msg)
	require.NoError(t, err)

	err = compressor.Close()
	require.NoError(t, err)

	return base64.URLEncoding.EncodeToString(compressed.Bytes())
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}
