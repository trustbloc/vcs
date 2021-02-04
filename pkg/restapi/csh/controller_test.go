/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package csh_test

import (
	"testing"

	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edge-service/pkg/restapi/csh"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation"
)

func TestNew(t *testing.T) {
	t.Run("returns an instance", func(t *testing.T) {
		c, err := csh.New(config(t))
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestController_GetOperations(t *testing.T) {
	c, err := csh.New(config(t))
	require.NoError(t, err)
	require.True(t, len(c.GetOperations()) > 0)
}

func config(t *testing.T) *operation.Config {
	t.Helper()

	return &operation.Config{
		StoreProvider: mockstore.NewMockStoreProvider(),
		Aries: &operation.AriesConfig{
			KMS:    &mockkms.KeyManager{},
			Crypto: &mockcrypto.Crypto{},
		},
	}
}
