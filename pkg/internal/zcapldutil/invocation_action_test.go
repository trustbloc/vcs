/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapldutil_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/internal/zcapldutil"
)

func TestCapabilityInvocationAction(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			path           string
			method         string
			expectedAction string
		}{
			{"/v1/keystores/{key_store_id}/keys", http.MethodPost, "createKey"},
			{"/v1/keystores/{key_store_id}/keys", http.MethodPut, "importKey"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}", http.MethodGet, "exportKey"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/sign", http.MethodPost, "sign"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/verify", http.MethodPost, "verify"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/encrypt", http.MethodPost, "encrypt"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/decrypt", http.MethodPost, "decrypt"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/computemac", http.MethodPost, "computeMAC"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/verifymac", http.MethodPost, "verifyMAC"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/signmulti", http.MethodPost, "signMulti"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/verifymulti", http.MethodPost, "verifyMulti"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/deriveproof", http.MethodPost, "deriveProof"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/verifyproof", http.MethodPost, "verifyProof"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/easy", http.MethodPost, "easy"},
			{"/v1/keystores/{key_store_id}/easyopen", http.MethodPost, "easyOpen"},
			{"/v1/keystores/{key_store_id}/sealopen", http.MethodPost, "sealOpen"},
			{"/v1/keystores/{key_store_id}/wrap", http.MethodPost, "wrap"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/wrap", http.MethodPost, "wrap"},
			{"/v1/keystores/{key_store_id}/keys/{key_id}/unwrap", http.MethodPost, "unwrap"},
		}

		for _, tt := range tests {
			t.Run(tt.expectedAction, func(t *testing.T) {
				req := &http.Request{
					URL:    &url.URL{Path: tt.path},
					Method: tt.method,
				}

				action, err := zcapldutil.CapabilityInvocationAction(req)

				require.NoError(t, err)
				require.Equal(t, tt.expectedAction, action)
			})
		}
	})

	t.Run("Error", func(t *testing.T) {
		tests := []struct {
			path        string
			method      string
			expectedErr string
		}{
			{"/v1/keystores/{key_store_id}/keys/{key_id}/sign", http.MethodGet, "unsupported operation: GET /sign"},
			{"/v1/keystores/{key_store_id}/keys", http.MethodGet, "unsupported operation: GET /keys"},
			{"/v1/keystores/{key_store_id}", http.MethodPost, "invalid path"},
			{"/v1/keystores/did", http.MethodPost, "invalid path"},
			{"/v1/keystores", http.MethodPost, "invalid path"},
			{"", http.MethodGet, "invalid path"},
		}

		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s%s", tt.method, strings.ReplaceAll(tt.path, "/", "_")), func(t *testing.T) {
				req := &http.Request{
					URL:    &url.URL{Path: tt.path},
					Method: tt.method,
				}

				action, err := zcapldutil.CapabilityInvocationAction(req)

				require.Empty(t, action)
				require.EqualError(t, err, tt.expectedErr)
			})
		}
	})
}
