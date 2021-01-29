/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package csh_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/csh"
)

func TestNew(t *testing.T) {
	t.Run("returns an instance", func(t *testing.T) {
		c, err := csh.New(nil)
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestController_GetOperations(t *testing.T) {
	c, err := csh.New(nil)
	require.NoError(t, err)
	require.True(t, len(c.GetOperations()) > 0)
}
