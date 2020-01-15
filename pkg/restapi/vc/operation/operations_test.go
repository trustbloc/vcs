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

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	log "github.com/sirupsen/logrus"

	"github.com/stretchr/testify/require"
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

func TestCreateCredentialHandler(t *testing.T) {
	op := New()

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
		require.Equal(t, ID, vc.ID)
	})
	t.Run("create credential error by passing invalid request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "/credentials", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), "Receieved invalid request: EOF")
	})
	t.Run("create credential error by passing invalid credential object", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "/credentials", bytes.NewBuffer([]byte(testIncorrectCredential)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(),
			"validation failed for vc: failed to create new credential: build new credential: "+
				"fill credential types from raw: credential type of unknown structure")
	})
	t.Run("create credential error unable to write a response while reading the request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "/credentials", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rw := mockResponseWriter{}
		createCredentialHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, logContents.String(),
			"Failed to write response for credential creation failure (unable to read request)")
	})
	t.Run("create credential error while writing the create credential failure", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "/credentials", bytes.NewBuffer([]byte(testIncorrectCredential)))
		require.NoError(t, err)
		rw := mockResponseWriter{}
		createCredentialHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, logContents.String(),
			"Failed to write response for create credential failure")
	})
}

func TestOperation_WriteResponse(t *testing.T) {
	svc := New()
	require.NotNil(t, svc)
	svc.writeResponse(&httptest.ResponseRecorder{}, "token")
}

func TestCreate(t *testing.T) {
	b := mockResponseWriter{}
	op := New()
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
