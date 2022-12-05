/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package otp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPinGenerator(t *testing.T) {
	gen := NewPinGenerator()
	for i := 0; i < 100; i++ {
		assert.Len(t, gen.Generate(), 6)
	}
}

func TestPinGeneratorVerify(t *testing.T) {
	gen := NewPinGenerator()

	t.Run("success", func(t *testing.T) {
		assert.True(t, gen.Validate("123", "123"))
	})

	t.Run("fail", func(t *testing.T) {
		assert.False(t, gen.Validate("1234", "123"))
	})
}
