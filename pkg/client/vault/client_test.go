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

		v := New(serv.URL, WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}))

		p, err := v.GetDocMetaData("v1", "doc1")
		require.NoError(t, err)
		require.Equal(t, "test", p.ID)
	})
}

func TestClient_CreateVault(t *testing.T) {
	t.Run("Send request (error)", func(t *testing.T) {
		_, err := New("").CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
	})

	t.Run("Invalid URL", func(t *testing.T) {
		_, err := New("http://user^foo.com").CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character \"^\" in host name")
	})

	t.Run("Unmarshal (error)", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, err := fmt.Fprint(w, "wrongValue")
			require.NoError(t, err)
		}))
		defer serv.Close()

		_, err := New(serv.URL).CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal to CreatedVault")
	})

	t.Run("Success", func(t *testing.T) {
		const ID = "ID"

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			p := vault.CreatedVault{ID: ID}
			bytes, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		p, err := New(serv.URL).CreateVault()
		require.NoError(t, err)
		require.Equal(t, ID, p.ID)
	})
}

func TestClient_CreateAuthorization(t *testing.T) {
	const (
		vID = "vID"
		rp  = "rp"
	)

	t.Run("Send request (error)", func(t *testing.T) {
		_, err := New("").CreateAuthorization(vID, rp, &vault.AuthorizationsScope{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
	})

	t.Run("Unmarshal (error)", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, err := fmt.Fprint(w, "wrongValue")
			require.NoError(t, err)
		}))
		defer serv.Close()

		_, err := New(serv.URL).CreateAuthorization(vID, rp, &vault.AuthorizationsScope{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal to CreatedAuthorization")
	})

	t.Run("Success", func(t *testing.T) {
		const ID = "ID"

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			p := vault.CreatedAuthorization{ID: ID}
			bytes, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		p, err := New(serv.URL).CreateAuthorization(vID, rp, &vault.AuthorizationsScope{})
		require.NoError(t, err)
		require.Equal(t, ID, p.ID)
	})
}

func TestClient_SaveDoc(t *testing.T) {
	const (
		vID = "vID"
		ID  = "ID"
	)

	t.Run("Send request (error)", func(t *testing.T) {
		_, err := New("").SaveDoc(vID, ID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
	})

	t.Run("Unmarshal (error)", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, err := fmt.Fprint(w, "wrongValue")
			require.NoError(t, err)
		}))
		defer serv.Close()

		_, err := New(serv.URL).SaveDoc(vID, ID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal to DocumentMetadata")
	})

	t.Run("Success", func(t *testing.T) {
		const ID = "ID"

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			p := vault.DocumentMetadata{ID: ID}
			bytes, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		p, err := New(serv.URL).SaveDoc(vID, ID, nil)
		require.NoError(t, err)
		require.Equal(t, ID, p.ID)
	})
}

func TestClient_GetAuthorization(t *testing.T) {
	t.Run("Send request (error)", func(t *testing.T) {
		_, err := New("").GetAuthorization("vid", "id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
	})

	t.Run("Unmarshal (error)", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := fmt.Fprint(w, "wrongValue")
			require.NoError(t, err)
		}))
		defer serv.Close()

		_, err := New(serv.URL).GetAuthorization("vid", "id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal to CreatedAuthorization")
	})

	t.Run("Success", func(t *testing.T) {
		const ID = "ID"

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.CreatedAuthorization{ID: ID}
			bytes, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		p, err := New(serv.URL).GetAuthorization("vid", "id")
		require.NoError(t, err)
		require.Equal(t, ID, p.ID)
	})
}
