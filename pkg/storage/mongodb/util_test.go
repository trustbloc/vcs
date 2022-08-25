/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodb_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

type testStruct struct {
	Val1 string `json:"val1"`
	Val2 string `json:"val2"`
}

func TestProfileStore_StructureToMap(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		expected := &testStruct{
			Val1: "t1",
			Val2: "t2",
		}

		mapped, err := mongodb.StructureToMap(expected)
		require.NoError(t, err)
		require.Equal(t, mapped["val1"], expected.Val1)
		require.Equal(t, mapped["val2"], expected.Val2)
	})

	t.Run("Fail", func(t *testing.T) {
		_, err := mongodb.StructureToMap("")
		require.Error(t, err)
	})
}

func TestProfileStore_MapToStructure(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		out := &testStruct{}

		expected := map[string]interface{}{
			"val1": "t1",
			"val2": "t2",
		}

		err := mongodb.MapToStructure(expected, out)
		require.NoError(t, err)
		require.Equal(t, expected["val1"], out.Val1)
		require.Equal(t, expected["val2"], out.Val2)
	})

	t.Run("Fail", func(t *testing.T) {
		out := testStruct{}

		err := mongodb.MapToStructure(nil, out)
		require.Error(t, err)
	})
}
