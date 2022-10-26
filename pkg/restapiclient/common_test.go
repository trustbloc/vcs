/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapiclient

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommonInvalid(t *testing.T) {
	resp, err := sendInternal[string, string](
		context.TODO(),
		nil,
		" ",
		"fdsfds",
		nil,
	)

	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "net/http: invalid method")
}
