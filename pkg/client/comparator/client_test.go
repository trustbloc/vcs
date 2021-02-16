/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package comparator

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/openapi"
)

func TestClient_GetConfig(t *testing.T) {
	t.Run("test error from http post", func(t *testing.T) {
		v := New("")

		_, err := v.GetConfig()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
	})

	t.Run("test http post return 500 status", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v := New(serv.URL)

		_, err := v.GetConfig()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read response body for status 500")
	})

	t.Run("test error from unmarshal resp to config response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := fmt.Fprint(w, "wrongValue")
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New(serv.URL)

		_, err := v.GetConfig()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal resp to comparator config")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			did := "test"
			p := openapi.Config{Did: &did}
			bytes, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New(serv.URL, WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))

		p, err := v.GetConfig()
		require.NoError(t, err)
		require.Equal(t, "test", *p.Did)
	})
}

func TestClient_Compare(t *testing.T) {
	t.Run("test error from http post", func(t *testing.T) {
		v := New("")

		eq := &openapi.EqOp{}
		query := make([]openapi.Query, 0)
		query = append(query, &openapi.DocQuery{})
		eq.SetArgs(query)

		cr := openapi.Comparison{}
		cr.SetOp(eq)

		_, err := v.Compare(cr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
	})

	t.Run("test http post return 500 status", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v := New(serv.URL)

		eq := &openapi.EqOp{}
		query := make([]openapi.Query, 0)
		query = append(query, &openapi.DocQuery{})
		eq.SetArgs(query)

		cr := openapi.Comparison{}
		cr.SetOp(eq)

		_, err := v.Compare(cr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read response body for status 500")
	})

	t.Run("test error from unmarshal resp to compare response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := fmt.Fprint(w, "wrongValue")
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New(serv.URL)

		eq := &openapi.EqOp{}
		query := make([]openapi.Query, 0)
		query = append(query, &openapi.DocQuery{})
		eq.SetArgs(query)

		cr := openapi.Comparison{}
		cr.SetOp(eq)

		_, err := v.Compare(cr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal resp to comparator compare result")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := openapi.ComparisonResult{Result: true}
			bytes, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New(serv.URL)

		eq := &openapi.EqOp{}
		query := make([]openapi.Query, 0)
		docID := "docID"
		vaultID := "vaultID"
		query = append(query, &openapi.DocQuery{DocID: &docID, VaultID: &vaultID})
		eq.SetArgs(query)

		cr := openapi.Comparison{}
		cr.SetOp(eq)

		r, err := v.Compare(cr)
		require.NoError(t, err)
		require.True(t, r)
	})
}
