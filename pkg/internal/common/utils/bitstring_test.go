/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitString(t *testing.T) {
	t.Run("test error position is invalid", func(t *testing.T) {
		bitString := NewBitString(5)

		_, err := bitString.Get(9)
		require.Error(t, err)
		require.Contains(t, err.Error(), "position is invalid")

		err = bitString.Set(-1, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "position is invalid")
	})

	t.Run("test error decode bits", func(t *testing.T) {
		_, err := DecodeBits("!!!!wrongvalue")
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data at input")
	})

	t.Run("test success", func(t *testing.T) {
		bitString := NewBitString(17)

		err := bitString.Set(1, true)
		require.NoError(t, err)

		bitSet, err := bitString.Get(1)
		require.NoError(t, err)
		require.True(t, bitSet)

		bitSet, err = bitString.Get(0)
		require.NoError(t, err)
		require.False(t, bitSet)

		encodeBits, err := bitString.EncodeBits()
		require.NoError(t, err)

		bitStr, err := DecodeBits(encodeBits)
		require.NoError(t, err)

		bitSet, err = bitStr.Get(1)
		require.NoError(t, err)
		require.True(t, bitSet)

		bitSet, err = bitStr.Get(0)
		require.NoError(t, err)
		require.False(t, bitSet)

		err = bitStr.Set(1, false)
		require.NoError(t, err)

		bitSet, err = bitStr.Get(1)
		require.NoError(t, err)
		require.False(t, bitSet)
	})
}
