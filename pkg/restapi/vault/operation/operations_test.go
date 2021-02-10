/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edv/pkg/restapi/messages"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
	. "github.com/trustbloc/edge-service/pkg/restapi/vault/operation"
)

func TestCreateVault(t *testing.T) {
	const path = "/vaults"

	t.Run("Internal error", func(t *testing.T) {
		v := newVaultMock()
		v.createVaultFn = func() (*vault.CreatedVault, error) {
			return nil, errors.New("test")
		}

		operation := New(v)

		h := handlerLookup(t, operation, CreateVaultPath, http.MethodPost)

		respBody, code := sendRequestToHandler(t, h, nil, path)

		require.Equal(t, http.StatusInternalServerError, code)

		var errResp *model.ErrorResponse

		require.NoError(t, json.NewDecoder(respBody).Decode(&errResp))
		require.NotEmpty(t, errResp.Message)
	})

	t.Run("Create vault", func(t *testing.T) {
		operation := New(newVaultMock())

		h := handlerLookup(t, operation, CreateVaultPath, http.MethodPost)

		respBody, code := sendRequestToHandler(t, h, strings.NewReader("{}"), path)

		require.Equal(t, http.StatusCreated, code)

		var resp *vault.CreatedVault

		require.NoError(t, json.NewDecoder(respBody).Decode(&resp))

		require.NotEmpty(t, resp.ID)
		require.NotEmpty(t, resp.KMS.URI)
		require.NotEmpty(t, resp.KMS.AuthToken)
		require.NotEmpty(t, resp.EDV.URI)
		require.NotEmpty(t, resp.EDV.AuthToken)
	})
}

func TestSaveDoc(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		const path = "/vaults/vaultID1/docs"

		v := newVaultMock()
		v.saveDocFn = func(vaultID, id string, content interface{}) (*vault.DocumentMetadata, error) {
			return nil, errors.New("test")
		}

		operation := New(v)

		h := handlerLookup(t, operation, SaveDocPath, http.MethodPost)
		res, code := sendRequestToHandler(t, h, strings.NewReader(`{}`), path)

		require.Equal(t, http.StatusInternalServerError, code)

		var errResp *model.ErrorResponse

		require.NoError(t, json.NewDecoder(res).Decode(&errResp))
	})
	t.Run("JSON error", func(t *testing.T) {
		const path = "/vaults/vaultID1/docs"

		operation := New(newVaultMock())

		h := handlerLookup(t, operation, SaveDocPath, http.MethodPost)
		res, code := sendRequestToHandler(t, h, strings.NewReader(`{`), path)

		require.Equal(t, http.StatusBadRequest, code)

		var errResp *model.ErrorResponse

		require.NoError(t, json.NewDecoder(res).Decode(&errResp))
		require.Contains(t, errResp.Message, "unexpected EOF")
	})
	t.Run("Error (generate ID)", func(t *testing.T) {
		const path = "/vaults/vaultID1/docs"

		operation := New(newVaultMock())
		operation.GenerateID = func() (string, error) {
			return "", errors.New("test error")
		}

		h := handlerLookup(t, operation, SaveDocPath, http.MethodPost)
		res, code := sendRequestToHandler(t, h, strings.NewReader(`{}`), path)

		require.Equal(t, http.StatusInternalServerError, code)

		var errResp *model.ErrorResponse

		require.NoError(t, json.NewDecoder(res).Decode(&errResp))
		require.Contains(t, errResp.Message, "test error")
	})
	t.Run("Success", func(t *testing.T) {
		const path = "/vaults/vaultID1/docs"

		operation := New(newVaultMock())

		h := handlerLookup(t, operation, SaveDocPath, http.MethodPost)
		res, code := sendRequestToHandler(t, h, strings.NewReader(`{}`), path)

		require.Equal(t, http.StatusCreated, code)

		var resp *vault.DocumentMetadata

		require.NoError(t, json.NewDecoder(res).Decode(&resp))

		require.NotEmpty(t, resp.ID)
		require.NotEmpty(t, resp.URI)
	})
}

func TestGetDocMetadata(t *testing.T) {
	const path = "/vaults/vaultID1/docs/docID1/metadata"

	t.Run("Internal error", func(t *testing.T) {
		v := newVaultMock()
		v.getDocMetadataFn = func(_, _ string) (*vault.DocumentMetadata, error) {
			return nil, errors.New("test")
		}

		operation := New(v)

		h := handlerLookup(t, operation, GetDocMetadataPath, http.MethodGet)

		respBody, code := sendRequestToHandler(t, h, nil, path)

		require.Equal(t, http.StatusInternalServerError, code)

		var errResp *model.ErrorResponse

		require.NoError(t, json.NewDecoder(respBody).Decode(&errResp))
		require.NotEmpty(t, errResp.Message)
	})

	t.Run("Not found", func(t *testing.T) {
		v := newVaultMock()
		v.getDocMetadataFn = func(_, _ string) (*vault.DocumentMetadata, error) {
			return nil, errors.New(messages.ErrDocumentNotFound.Error() + ".")
		}

		operation := New(v)

		h := handlerLookup(t, operation, GetDocMetadataPath, http.MethodGet)

		respBody, code := sendRequestToHandler(t, h, nil, path)

		require.Equal(t, http.StatusNotFound, code)

		var errResp *model.ErrorResponse

		require.NoError(t, json.NewDecoder(respBody).Decode(&errResp))
		require.NotEmpty(t, errResp.Message)
	})

	t.Run("Success", func(t *testing.T) {
		operation := New(newVaultMock())

		h := handlerLookup(t, operation, GetDocMetadataPath, http.MethodGet)
		res, code := sendRequestToHandler(t, h, strings.NewReader(`{}`), path)

		require.Equal(t, http.StatusOK, code)

		var resp *vault.DocumentMetadata

		require.NoError(t, json.NewDecoder(res).Decode(&resp))

		require.NotEmpty(t, resp.ID)
		require.NotEmpty(t, resp.URI)
	})
}

func TestCreateAuthorization(t *testing.T) {
	const path = "/vaults/vaultID1/authorizations"

	operation := New(newVaultMock())

	h := handlerLookup(t, operation, CreateAuthorizationPath, http.MethodPost)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusCreated, code)
}

func TestGetAuthorization(t *testing.T) {
	const path = "/vaults/vaultID1/authorizations/authID1"

	operation := New(newVaultMock())

	h := handlerLookup(t, operation, GetAuthorizationPath, http.MethodGet)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusOK, code)
}

func TestDeleteVault(t *testing.T) {
	const path = "/vaults/vaultID1"

	operation := New(newVaultMock())

	h := handlerLookup(t, operation, DeleteVaultPath, http.MethodDelete)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusOK, code)
}

func TestWriteResponse(t *testing.T) {
	rec := httptest.NewRecorder()

	(&Operation{}).WriteResponse(rec, make(chan int), http.StatusInternalServerError)
	reader := rec.Result().Body

	res, err := ioutil.ReadAll(reader)
	require.NoError(t, reader.Close())
	require.NoError(t, err)
	require.Empty(t, res)
}

func TestDeleteAuthorization(t *testing.T) {
	const path = "/vaults/vaultID1/authorizations/authID1"

	operation := New(newVaultMock())

	h := handlerLookup(t, operation, DeleteAuthorizationPath, http.MethodDelete)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusOK, code)
}

// sendRequestToHandler reads response from given http handle func.
func sendRequestToHandler(t *testing.T, h support.Handler, reqBody io.Reader, path string) (*bytes.Buffer, int) {
	// prepare request
	req, err := http.NewRequest(h.Method(), path, reqBody)
	require.NoError(t, err)

	// prepare router
	router := mux.NewRouter()

	router.HandleFunc(h.Path(), h.Handle()).Methods(h.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// serve http on given response and request
	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code
}

func handlerLookup(t *testing.T, op *Operation, lookup, method string) rest.Handler {
	t.Helper()

	for _, h := range op.GetRESTHandlers() {
		if h.Path() == lookup && h.Method() == method {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func newVaultMock() *vaultMock {
	return &vaultMock{
		createVaultFn: func() (*vault.CreatedVault, error) {
			return &vault.CreatedVault{
				ID: "did:key:z6MkiCxgAoySWK",
				Authorization: &vault.Authorization{
					EDV: &vault.Location{
						URI:       "localhost:7777/encrypted-data-vaults/HwtZ1bUn4SzXoQRoX9br6m",
						AuthToken: "H4sIAAAAAAAA_5SSX3OrNhTEv8u5j4UEZP5JT3VIHGM7jolNYnMn0xFC2DJ",
					},
					KMS: &vault.Location{
						URI:       "/kms/keystores/c0ehl35ioude7fdbosfg",
						AuthToken: "mcwMlgYIHI3JNWk0rk3BH6U6NDSyQglTNS4uWCA4EGgkqW4kWGkjFeoGs",
					},
				},
			}, nil
		},
		saveDocFn: func(vaultID, id string, content interface{}) (*vault.DocumentMetadata, error) {
			return &vault.DocumentMetadata{
				ID:  "M3aS9xwj8ybCwHkEiCJJR1",
				URI: "localhost:7777/encrypted-data-vaults/HwtZ1bUn4SzXoQRoX9br6m/documents/M3aS9xwj8ybCwHkEiCJJR1",
			}, nil
		},
		getDocMetadataFn: func(vaultID, id string) (*vault.DocumentMetadata, error) {
			return &vault.DocumentMetadata{
				ID:  "M3aS9xwj8ybCwHkEiCJJR1",
				URI: "localhost:7777/encrypted-data-vaults/HwtZ1bUn4SzXoQRoX9br6m/documents/M3aS9xwj8ybCwHkEiCJJR1",
			}, nil
		},
	}
}

type vaultMock struct {
	createVaultFn    func() (*vault.CreatedVault, error)
	saveDocFn        func(vaultID, id string, content interface{}) (*vault.DocumentMetadata, error)
	getDocMetadataFn func(vaultID, docID string) (*vault.DocumentMetadata, error)
}

func (v *vaultMock) CreateVault() (*vault.CreatedVault, error) {
	return v.createVaultFn()
}

func (v *vaultMock) SaveDoc(vaultID, id string, content interface{}) (*vault.DocumentMetadata, error) {
	return v.saveDocFn(vaultID, id, content)
}

func (v *vaultMock) GetDocMetadata(vaultID, docID string) (*vault.DocumentMetadata, error) {
	return v.getDocMetadataFn(vaultID, docID)
}
