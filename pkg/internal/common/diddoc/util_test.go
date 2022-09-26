/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddoc

import (
	"testing"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
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

	key, err = GetKeyIDFromVerificationMethod(didID + "#" + keyID + "#" + keyID)
	require.Error(t, err)
	require.Equal(t, "", key)
}

func TestGetDIDDocFromVerificationMethod(t *testing.T) {
	did, err := GetDIDDocFromVerificationMethod(didID, &vdrmock.MockVDRegistry{})
	require.Error(t, err)
	require.Nil(t, did)

	did, err = GetDIDDocFromVerificationMethod(keyID, &vdrmock.MockVDRegistry{})
	require.Error(t, err)
	require.Nil(t, did)

	did, err = GetDIDDocFromVerificationMethod(didID+"#"+keyID, &vdrmock.MockVDRegistry{})
	require.Error(t, err)
	require.Nil(t, did)

	did, err = GetDIDDocFromVerificationMethod(didID+"#"+keyID, &vdrmock.MockVDRegistry{
		ResolveValue: &diddoc.Doc{},
	})
	require.NoError(t, err)
	require.NotNil(t, did)
}
