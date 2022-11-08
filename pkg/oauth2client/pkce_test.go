/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oauth2client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPKCE(t *testing.T) {
	p := NewOAuth2Client()

	t.Run("test generate", func(t *testing.T) {
		verifier, challenge, method, err := p.GeneratePKCE()
		assert.NoError(t, err)
		assert.NotEmpty(t, verifier)
		assert.NotEmpty(t, challenge)
		assert.Equal(t, "S256", method)
	})

	t.Run("test generate", func(t *testing.T) {
		verifier, challenge, method, err := p.GeneratePKCEFromBytes([]byte("awesome-random-string"))
		assert.NoError(t, err)
		assert.Equal(t, "YXdlc29tZS1yYW5kb20tc3RyaW5n", verifier)
		assert.Equal(t, "DCtl4-KkVg7z7a7M_dM8qYD2-OOywme-w06WyI590m8", challenge)
		assert.Equal(t, "S256", method)
	})
}
