/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comparator_test

import (
	"fmt"
	"testing"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/comparator"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		controller, err := comparator.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		_, err := comparator.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store")}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})
}

func TestController_GetOperations(t *testing.T) {
	s := &mockstorage.MockStore{Store: make(map[string][]byte)}
	s.Store["config"] = []byte(`{}`)
	controller, err := comparator.New(&operation.Config{CSHBaseURL: "https://localhost",
		StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 4, len(ops))
}
