/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
)

const (
	testCreateCredentialRequest = `{
"context":"https://www.w3.org/2018/credentials/examples/v1",
"type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "university": "MIT"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },

  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  }
}`
)
const (
	testIncorrectCredential = `{
		"credentialSubject": {
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"degree": {
		"type": "BachelorDegree",
		"university": "MIT"
		},
		"name": "Jayden Doe",
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
		},
		
		"issuer": {
		"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
		"name": "Example University"
		}
}`
)
const (
	testIssuerProfile = `{
		"did": "did:peer:22",
		"uri": "https://example.com/credentials"
}`
)
const (
	testIncorrectIssuerProfile = `{
		"did": "did:peer:22",
		"uri": "&&%^)$"
}`
)

const validVC = `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "id": "http://example.edu/credentials/1872",
  "type": "VerifiableCredential",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  },
  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },
  "issuanceDate": "2010-01-01T19:23:24Z"
}`

// VC without issuer
const invalidVC = `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "id": "http://example.edu/credentials/1872",
  "type": "VerifiableCredential",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  },
  "issuanceDate": "2010-01-01T19:23:24Z"
}`

func TestCreateCredentialHandler(t *testing.T) {
	op, err := New(memstore.NewProvider())
	require.NoError(t, err)

	createCredentialHandler := getHandler(t, op, createCredentialEndpoint)

	var logContents bytes.Buffer

	log.SetOutput(&logContents)

	t.Run("create credential success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
			bytes.NewBuffer([]byte(testCreateCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createCredentialHandler.Handle().ServeHTTP(rr, req)
		vc := verifiable.Credential{}

		err = json.Unmarshal(rr.Body.Bytes(), &vc)
		require.NoError(t, err)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f", vc.Issuer.ID)
		require.Equal(t, "Example University", vc.Issuer.Name)
		require.Equal(t, id, vc.ID)
	})
	t.Run("create credential error by passing invalid request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), "Failed to write response for invalid request received")
	})
	t.Run("create credential error by passing invalid credential object", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
			bytes.NewBuffer([]byte(testIncorrectCredential)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(),
			"Failed to write response for create credential failure")
	})
	t.Run("create credential error unable to write a response while reading the request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rw := mockResponseWriter{}
		createCredentialHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, logContents.String(),
			"Unable to send error message, response writer failed")
	})
}

func TestVerifyCredentialHandler(t *testing.T) {
	op, err := New(memstore.NewProvider())
	require.NoError(t, err)

	verifyCredentialHandler := getHandler(t, op, verifyCredentialEndpoint)

	t.Run("verify credential success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, bytes.NewBuffer([]byte(validVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		response := VerifyCredentialResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, true, response.Verified)
		require.Equal(t, "success", response.Message)
	})

	t.Run("test error while reading http request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, nil)
		require.NoError(t, err)

		req.Body = &mockReader{}
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "reader error")
	})

	t.Run("test error due to passing invalid credential object", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, bytes.NewBuffer([]byte(invalidVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		response := VerifyCredentialResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, false, response.Verified)
		require.Contains(t, response.Message, "unsupported format of issuer")
	})
}

func TestCreateProfileHandler(t *testing.T) {
	op, err := New(memstore.NewProvider())
	require.NoError(t, err)

	createProfileHandler := getHandler(t, op, createProfileEndpoint)

	var logContents bytes.Buffer

	log.SetOutput(&logContents)

	t.Run("create profile success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		profile := ProfileResponse{}

		err = json.Unmarshal(rr.Body.Bytes(), &profile)
		require.NoError(t, err)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, profile.ID)
		require.Contains(t, profile.URI, "https://example.com/credentials")
	})
	t.Run("missing DID information", func(t *testing.T) {
		prBytes, err := json.Marshal(ProfileRequest{})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer(prBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), "missing DID information")
	})
	t.Run("missing URI information", func(t *testing.T) {
		prBytes, err := json.Marshal(ProfileRequest{DID: "test"})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer(prBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), "missing URI information")
	})
	t.Run("create profile error by passing invalid request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), "Failed to write response for invalid request received")
	})
	t.Run("create profile error by internal create profile failure", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIncorrectIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse the uri: parse &&%^)$: invalid URL escape")
	})

	t.Run("create profile error unable to write a response while reading the request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rw := mockResponseWriter{}
		createProfileHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, logContents.String(),
			"Unable to send error message, response writer failed")
	})
	t.Run("create profile error while saving the profile", func(t *testing.T) {
		op, err := New(memstore.NewProvider())
		require.NoError(t, err)
		op.profileStore = NewProfile(&mockStore{
			get: func(s string) (bytes []byte, e error) {
				return nil, storage.ErrValueNotFound
			},
			put: func(s string, bytes []byte) error {
				return errors.New("db error while saving profile")
			}})

		createProfileHandler = getHandler(t, op, createProfileEndpoint)
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte(testIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "db error while saving profile")
	})
}

func TestGetProfileHandler(t *testing.T) {
	op, err := New(memstore.NewProvider())
	require.NoError(t, err)

	getProfileHandler := getHandler(t, op, getProfileEndpoint)

	var logContents bytes.Buffer

	log.SetOutput(&logContents)

	notFoundID := "test"
	req, err := http.NewRequest(http.MethodGet,
		"/profile/"+notFoundID,
		bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[profilePathVariable] = notFoundID

	req = mux.SetURLVars(req, urlVars)

	t.Run("get profile success", func(t *testing.T) {
		profile := createProfileSuccess(t, op)

		r, err := http.NewRequest(http.MethodGet,
			"/profile/"+profile.ID,
			bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[profilePathVariable] = profile.ID
		req = mux.SetURLVars(r, urlVars)

		getProfileHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		profileResponse := &ProfileResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), profileResponse)
		require.NoError(t, err)
		require.Equal(t, profileResponse.ID, profile.ID)
		require.Equal(t, profileResponse.URI, profile.URI)
	})
	t.Run("get profile error, bad request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet,
			"/profile/"+notFoundID,
			bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		getProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func createProfileSuccess(t *testing.T, op *Operation) *ProfileResponse {
	req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte(testIssuerProfile)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createProfileEndpoint := getHandler(t, op, createProfileEndpoint)
	createProfileEndpoint.Handle().ServeHTTP(rr, req)

	profile := &ProfileResponse{}

	err = json.Unmarshal(rr.Body.Bytes(), &profile)
	require.NoError(t, err)

	require.Equal(t, http.StatusCreated, rr.Code)
	require.NotEmpty(t, profile.ID)

	return profile
}

func TestOperation_parseAndGetURL(t *testing.T) {
	t.Run("parse uri success", func(t *testing.T) {
		resp, err := parseAndGetURI("http://example.edu/credentials")
		require.NotNil(t, resp)
		require.NoError(t, err)
	})
	t.Run("parse uri failed", func(t *testing.T) {
		resp, err := parseAndGetURI("//not-valid.&&%^)$")
		require.Empty(t, resp)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse the uri")
	})
}

func TestCreate(t *testing.T) {
	b := mockResponseWriter{}
	op, err := New(memstore.NewProvider())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
		bytes.NewBuffer([]byte(testCreateCredentialRequest)))
	require.NoError(t, err)

	var logContents bytes.Buffer

	log.SetOutput(&logContents)

	op.createCredentialHandler(b, req)
	require.Contains(t, logContents.String(), "Unable to send error response, response writer failed")
}

func getHandler(t *testing.T, op *Operation, lookup string) Handler {
	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *Operation, lookup string) Handler {
	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

type mockResponseWriter struct {
}

func (b mockResponseWriter) Header() http.Header {
	panic("implement me")
}

func (b mockResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("response writer failed")
}

func (b mockResponseWriter) WriteHeader(statusCode int) {
}

type mockStore struct {
	put func(string, []byte) error
	get func(string) ([]byte, error)
}

// Put stores the key and the record
func (m *mockStore) Put(k string, v []byte) error {
	return m.put(k, v)
}

// Get fetches the record based on key
func (m *mockStore) Get(k string) ([]byte, error) {
	return m.get(k)
}

type mockReader struct{}

func (r *mockReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("reader error")
}

func (r *mockReader) Close() error {
	return nil
}
