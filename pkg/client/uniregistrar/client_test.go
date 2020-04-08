/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package uniregistrar

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	didmethodoperation "github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
)

func TestClient_CreateDID(t *testing.T) {
	t.Run("test error from http post", func(t *testing.T) {
		v := New()

		did, _, err := v.CreateDID("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
		require.Empty(t, did)
	})

	t.Run("test http post return 500 status", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v := New()

		did, _, err := v.CreateDID(serv.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read response body for status 500")
		require.Empty(t, did)
	})

	t.Run("test error from unmarshal resp to register response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := fmt.Fprint(w, "wrongValue")
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New()

		did, _, err := v.CreateDID(serv.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal resp to register response")
		require.Empty(t, did)
	})

	t.Run("test server return wrong jod id", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			bytes, err := json.Marshal(didmethodoperation.RegisterResponse{JobID: "wrongValue"})
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New()

		did, _, err := v.CreateDID(serv.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "register response jobID=wrongValue not equal")
		require.Empty(t, did)
	})

	t.Run("test server return state failure", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			bytes, err := json.Marshal(didmethodoperation.RegisterResponse{JobID: "",
				DIDState: didmethodoperation.DIDState{Reason: "server error",
					State: didmethodoperation.RegistrationStateFailure}})
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New()

		did, _, err := v.CreateDID(serv.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failure from uniregistrar server error")
		require.Empty(t, did)
	})

	t.Run("test server return unknown state", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			bytes, err := json.Marshal(didmethodoperation.RegisterResponse{JobID: "",
				DIDState: didmethodoperation.DIDState{State: "not available"}})
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New()

		did, _, err := v.CreateDID(serv.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "uniregistrar return unknown state")
		require.Empty(t, did)
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req didmethodoperation.RegisterDIDRequest

			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			require.Equal(t, 1, len(req.Options))
			require.Equal(t, "v1", req.Options["k1"])

			require.Equal(t, 1, len(req.AddPublicKeys))
			require.Equal(t, "key1", req.AddPublicKeys[0].ID)

			w.WriteHeader(http.StatusOK)
			bytes, err := json.Marshal(didmethodoperation.RegisterResponse{JobID: "",
				DIDState: didmethodoperation.DIDState{State: didmethodoperation.RegistrationStateFinished,
					Identifier: "did1"}})
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New(WithTLSConfig(&tls.Config{}))

		opts := make(map[string]string)

		opts["k1"] = "v1"

		did, _, err := v.CreateDID(serv.URL, WithOptions(opts), WithPublicKey(
			&didmethodoperation.PublicKey{ID: "key1", Type: "type1", Value: "value1"}))
		require.NoError(t, err)
		require.Equal(t, "did1", did)
	})
}
