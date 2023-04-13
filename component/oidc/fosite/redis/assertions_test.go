/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAssertions(t *testing.T) {
	s := Store{}

	assert.NotNil(t, s.assertInterface())
	assert.NotNil(t, s.assertInterface2())
	assert.NotNil(t, s.assertInterface3())
	assert.NotNil(t, s.assertInterface4())
	assert.NotNil(t, s.assertInterface5())
}
