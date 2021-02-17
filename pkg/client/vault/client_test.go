/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

func TestClient_GetDocMetaData(t *testing.T) {
	t.Run("test error from http post", func(t *testing.T) {
		v := New("")

		_, err := v.GetDocMetaData("v1", "doc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
	})

	t.Run("test http post return 500 status", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v := New(serv.URL)

		_, err := v.GetDocMetaData("v1", "doc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read response body for status 500")
	})

	t.Run("test error from unmarshal resp to profile response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := fmt.Fprint(w, "wrongValue")
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New(serv.URL)

		_, err := v.GetDocMetaData("v1", "doc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal resp to vault doc meta")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "test"}
			bytes, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New(serv.URL, WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))

		p, err := v.GetDocMetaData("v1", "doc1")
		require.NoError(t, err)
		require.Equal(t, "test", p.ID)
	})
}
