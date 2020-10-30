/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/stretchr/testify/require"
)

func TestResolve_vdr(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		op := New(&Config{
			RuleProvider: &mockRuleProvider{},
			KeyVDRI:      *key.New(),
		})

		proxyHandler := getHandler(t, op, resolveURL)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		})

		req.Header.Add(authorizationHeader, "token")
		req.Header.Add(acceptHeader, didLDJson)

		rr := httptest.NewRecorder()

		proxyHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("error - invalid DID", func(t *testing.T) {
		op := New(&Config{
			RuleProvider: &mockRuleProvider{},
		})

		proxyHandler := getHandler(t, op, resolveURL)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"did": "invalid",
		})

		rr := httptest.NewRecorder()

		proxyHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("error - unsupported DID method", func(t *testing.T) {
		op := New(&Config{
			RuleProvider: &mockRuleProvider{},
		})

		proxyHandler := getHandler(t, op, resolveURL)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"did": "did:unsupported:id",
		})

		rr := httptest.NewRecorder()

		proxyHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("error - failed to resolve DID", func(t *testing.T) {
		op := New(&Config{
			RuleProvider: &mockRuleProvider{},
			KeyVDRI:      *key.New(),
		})

		proxyHandler := getHandler(t, op, resolveURL)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"did": "did:key:abc",
		})

		rr := httptest.NewRecorder()

		proxyHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestResolve_proxy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "{}")
		}))
		defer dest.Close()

		op := New(&Config{
			RuleProvider: &mockRuleProvider{URL: dest.URL + "/identifiers/did:method:abc"},
		})

		proxyHandler := getHandler(t, op, resolveURL)

		req, err := http.NewRequest(http.MethodGet, "http://example.com/identifiers/did:method:abc", nil)
		require.NoError(t, err)

		req.Header.Add(authorizationHeader, "token")
		req.Header.Add(acceptHeader, didLDJson)

		rr := httptest.NewRecorder()

		proxyHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("error - rule provider error", func(t *testing.T) {
		op := New(&Config{
			RuleProvider: &mockRuleProvider{Err: errors.New("rule provider error")},
		})

		proxyHandler := getHandler(t, op, resolveURL)

		req, err := http.NewRequest(http.MethodGet, "http://example.com/identifiers/did:method:abc", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		proxyHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("error - destination returns 404", func(t *testing.T) {
		dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer dest.Close()

		op := New(&Config{
			RuleProvider: &mockRuleProvider{URL: dest.URL + "/identifiers/did:method:abc"},
		})

		proxyHandler := getHandler(t, op, resolveURL)

		req, err := http.NewRequest(http.MethodGet, "http://example.com/identifiers/did:method:abc", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		proxyHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("error - destination server not available", func(t *testing.T) {
		op := New(&Config{
			RuleProvider: &mockRuleProvider{URL: "https://213abfg8989.com/identifiers/did:method:abc"},
		})

		proxyHandler := getHandler(t, op, resolveURL)

		req, err := http.NewRequest(http.MethodGet, "http://example.com/identifiers/did:method:abc", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		proxyHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("error - invalid destination URL", func(t *testing.T) {
		op := New(&Config{
			RuleProvider: &mockRuleProvider{URL: "not a good one"},
		})

		proxyHandler := getHandler(t, op, resolveURL)

		req, err := http.NewRequest(http.MethodGet, "http://example.com/identifiers/did:method:abc", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		proxyHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func getHandler(t *testing.T, op *Operation, lookup string) Handler {
	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *Operation, lookup string) Handler {
	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers := op.GetRESTHandlers()

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

type mockRuleProvider struct {
	Err error
	URL string
}

func (p *mockRuleProvider) Transform(uri string) (string, error) {
	if p.Err != nil {
		return "", p.Err
	}

	return p.URL, nil
}
