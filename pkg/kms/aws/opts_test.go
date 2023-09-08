/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws //nolint:testpackage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpts(t *testing.T) {
	t.Run("options: defaults", func(t *testing.T) {
		options := newOpts()

		require.Equal(t, "", options.KeyAliasPrefix())
	})

	t.Run("options: set manually", func(t *testing.T) {
		options := newOpts()

		WithKeyAliasPrefix("keyaliasprefix")(options)

		require.Equal(t, "keyaliasprefix", options.KeyAliasPrefix())
	})

	t.Run("options: env vars", func(t *testing.T) {
		t.Setenv("AWS_KEY_ALIAS_PREFIX", "keyaliasprefix")

		options := newOpts()

		require.Equal(t, "keyaliasprefix", options.KeyAliasPrefix())
	})
}
