/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/kms"
)

func TestNewRegistry(t *testing.T) {
	r := kms.NewRegistry(nil, kms.Config{}, nil)
	require.NotNil(t, r)
}

func TestRegistry_GetKeyManager(t *testing.T) {
	t.Run("Default config local kms", func(t *testing.T) {
		r := kms.NewRegistry(nil, kms.Config{KMSType: kms.Local}, nil)
		require.NotNil(t, r)

		_, err := r.GetKeyManager(nil)
		require.NoError(t, err)
	})
}
