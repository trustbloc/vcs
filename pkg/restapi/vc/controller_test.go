/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edge-service/pkg/internal/mock"
)

func TestController_New(t *testing.T) {
	client := mock.NewMockEDVClient("test")
	controller, err := New(memstore.NewProvider(), client)
	require.NoError(t, err)
	require.NotNil(t, controller)
}

func TestController_GetOperations(t *testing.T) {
	client := mock.NewMockEDVClient("test")
	controller, err := New(memstore.NewProvider(), client)
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 6, len(ops))

	require.Equal(t, "/credential", ops[0].Path())
	require.Equal(t, http.MethodPost, ops[0].Method())
	require.NotNil(t, ops[0].Handle())
}
