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
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edge-service/pkg/internal/mock/edv"
)

func TestIssuerController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		controller, err := New(
			memstore.NewProvider(),
			client,
			&kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{},
			"",
			"issuer")
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		controller, err := New(&mockstore.Provider{
			ErrOpenStoreHandle: fmt.Errorf("error open store")}, client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "", "issuer")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestVerifierController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		controller, err := New(
			memstore.NewProvider(),
			client,
			&kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{},
			"",
			"verifier")
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		controller, err := New(&mockstore.Provider{
			ErrOpenStoreHandle: fmt.Errorf("error open store")}, client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "", "verifier")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestControllerInvalidMode_New(t *testing.T) {
	t.Run("must return error if an invalid mode is given", func(t *testing.T) {
		_, err := New(
			&mockstore.Provider{ErrOpenStoreHandle: fmt.Errorf("error open store")},
			edv.NewMockEDVClient("test", nil),
			&kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{},
			"",
			"invalid")
		require.Error(t, err)
	})
}

func TestIssuerController_GetOperations(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil)
	controller, err := New(
		memstore.NewProvider(),
		client,
		&kmsmock.CloseableKMS{},
		&vdrimock.MockVDRIRegistry{},
		"",
		"issuer")
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 8, len(ops))

	require.Equal(t, "/credential", ops[0].Path())
	require.Equal(t, http.MethodPost, ops[0].Method())
	require.NotNil(t, ops[0].Handle())
}

func TestVerifierController_GetOperations(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil)
	controller, err := New(
		memstore.NewProvider(),
		client,
		&kmsmock.CloseableKMS{},
		&vdrimock.MockVDRIRegistry{},
		"",
		"verifier")
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 1, len(ops))

	require.Equal(t, "/verify", ops[0].Path())
	require.Equal(t, http.MethodPost, ops[0].Method())
	require.NotNil(t, ops[0].Handle())
}
