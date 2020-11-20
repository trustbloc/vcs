/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"fmt"
	"net/http"
	"testing"

	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"
)

func TestService_CreateDIDKey(t *testing.T) {
	t.Run("test error from create did key", func(t *testing.T) {
		svc := New(&mockkms.KeyManager{CreateKeyErr: fmt.Errorf("failed to create")}, &mockcrypto.Crypto{})

		didKey, err := svc.CreateDIDKey()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create")
		require.Empty(t, didKey)
	})

	t.Run("test success", func(t *testing.T) {
		svc := New(&mockkms.KeyManager{}, &mockcrypto.Crypto{})

		didKey, err := svc.CreateDIDKey()
		require.NoError(t, err)
		require.NotEmpty(t, didKey)
	})
}

func TestService_SignHeader(t *testing.T) {
	t.Run("test error from sign header", func(t *testing.T) {
		svc := New(&mockkms.KeyManager{}, &mockcrypto.Crypto{})

		hdr, err := svc.SignHeader(&http.Request{Header: make(map[string][]string)}, []byte("{}"), "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating signature")
		require.Nil(t, hdr)
	})
}
