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
	r := kms.NewRegistry(&kms.Config{})
	require.NotNil(t, r)
}

func TestRegistry_GetKeyManager(t *testing.T) {
	t.Run("Default config local kms", func(t *testing.T) {
		r := kms.NewRegistry(&kms.Config{
			KMSType: kms.Local,
		})
		require.NotNil(t, r)

		_, err := r.GetKeyManager(nil)
		require.Equal(t, "no key defined for local secret lock", err.Error())
	})

	t.Run("Custom config local kms", func(t *testing.T) {
		r := kms.NewRegistry(&kms.Config{
			KMSType: "incorrect",
		})
		require.NotNil(t, r)

		_, err := r.GetKeyManager(&kms.Config{
			KMSType: kms.Local,
		})
		require.Equal(t, "no key defined for local secret lock", err.Error())
	})

	t.Run("Incorrect type", func(t *testing.T) {
		r := kms.NewRegistry(&kms.Config{
			KMSType: "incorrect",
		})
		require.NotNil(t, r)

		_, err := r.GetKeyManager(nil)
		require.Equal(t, "unsupported kms type \"incorrect\"", err.Error())
	})
}
