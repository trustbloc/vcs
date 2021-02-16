/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

func Test_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, err := fmt.Fprint(w, "{}")
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
		_, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{
			Store: s}, KeyManager: &mockkms.KeyManager{CrAndExportPubKeyErr: fmt.Errorf("failed to export")}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to export")
	})

	t.Run("test failed to get config", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.ErrGet = fmt.Errorf("failed to get config")
		_, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{
			Store: s}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get config")
	})
}

func TestOperation_CreateAuthorization(t *testing.T) {
	t.Run("TODO - creates an authorization", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{
			Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.CreateAuthorization(result, nil)
		require.Equal(t, http.StatusCreated, result.Code)
		require.Contains(t, result.Body.String(), "fakeZCAP")
	})
}

func TestOperation_Compare(t *testing.T) {
	t.Run("test bad request", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
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
		op, err := operation.New(&operation.Config{VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		cr := &openapi.ComparisonRequest{}
		eq := &openapi.EqOp{}
		query := make([]openapi.Query, 0)
		docID := "docID"
		vaultID := "vaultID"
		query = append(query, &openapi.DocQuery{DocID: &docID, VaultID: &vaultID})
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

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		cr := &openapi.ComparisonRequest{}
		eq := &openapi.EqOp{}
		query := make([]openapi.Query, 0)
		docID := "docID"
		vaultID := "vaultID"
		query = append(query, &openapi.DocQuery{DocID: &docID, VaultID: &vaultID})
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
		op, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{
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
		op, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{
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
		op, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{
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
		op, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{
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

func newReq(t *testing.T, method, path string, payload interface{}) *http.Request {
	t.Helper()

	var body io.Reader

	if payload != nil {
		raw, err := json.Marshal(payload)
		require.NoError(t, err)

		body = bytes.NewReader(raw)
	}

	return httptest.NewRequest(method, path, body)
}
