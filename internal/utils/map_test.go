/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/internal/utils"
)

func TestExtract(t *testing.T) {
	claimData := map[string]interface{}{
		"claim": map[string]interface{}{
			"value": map[string]interface{}{
				"xx": "example",
				"yy": map[string]interface{}{
					"zz": "nested example",
				},
			},
			"anotherKey": "anotherValue",
		},
	}

	keys := utils.ExtractKeys("$", claimData)

	sort.Strings(keys)

	assert.EqualValues(t, []string{
		"$.claim",
		"$.claim.anotherKey",
		"$.claim.value",
		"$.claim.value.xx",
		"$.claim.value.yy",
		"$.claim.value.yy.zz",
	}, keys)
}
