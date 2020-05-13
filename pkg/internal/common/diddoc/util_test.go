/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddoc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	didID = "did:test:abc"
	keyID = "key-1"
)

func TestGetDIDFromVerificationMethod(t *testing.T) {
	did, err := GetDIDFromVerificationMethod(didID + "#" + keyID)
	require.NoError(t, err)
	require.Equal(t, didID, did)

	did, err = GetDIDFromVerificationMethod(didID + keyID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "verificationMethod value did:test:abckey-1 should be in did#keyID format")
	require.Equal(t, "", did)
}

func TestGetKeyIDFromVerificationMethod(t *testing.T) {
	key, err := GetKeyIDFromVerificationMethod(didID + "#" + keyID)
	require.NoError(t, err)
	require.Equal(t, keyID, key)

	key, err = GetKeyIDFromVerificationMethod(didID + keyID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "verificationMethod value did:test:abckey-1 should be in did#keyID format")
	require.Equal(t, "", key)
}
