/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestController_New(t *testing.T) {
	controller, err := New()
	require.NoError(t, err)
	require.NotNil(t, controller)
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New()
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 1, len(ops))

	require.Equal(t, "/credential", ops[0].Path())
	require.Equal(t, http.MethodPost, ops[0].Method())
	require.NotNil(t, ops[0].Handle())
}
