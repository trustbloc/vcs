/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"fmt"
	"net/http"
	"testing"

	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	storagemock "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edge-service/pkg/internal/mock/edv"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		controller, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{}, &vdrimock.MockVDRIRegistry{})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		controller, err := New(&storagemock.Provider{
			ErrOpenStoreHandle: fmt.Errorf("error open store")}, client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil)
	controller, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{}, &vdrimock.MockVDRIRegistry{})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 6, len(ops))

	require.Equal(t, "/credential", ops[0].Path())
	require.Equal(t, http.MethodPost, ops[0].Method())
	require.NotNil(t, ops[0].Handle())
}
