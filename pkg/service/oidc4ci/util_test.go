package oidc4ci_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestMapping(t *testing.T) {
	t.Run("jwt", func(t *testing.T) {
		resp, err := oidc4ci.MapCredentialFormat("jwt")
		assert.NoError(t, err)
		assert.Equal(t, "jwt_vc_json", resp)
	})
	t.Run("ldp", func(t *testing.T) {
		resp, err := oidc4ci.MapCredentialFormat("ldp")
		assert.NoError(t, err)
		assert.Equal(t, "ldp_vc", resp)
	})

	t.Run("any", func(t *testing.T) {
		resp, err := oidc4ci.MapCredentialFormat("any")
		assert.Empty(t, resp)
		assert.ErrorContains(t, err, "unsupported vc mapping for format")
	})
}

func TestWithTtl(t *testing.T) {
	opt := &oidc4ci.InsertOptions{}
	oidc4ci.WithDocumentTTL(10 * time.Minute)(opt)
	assert.Equal(t, 10*time.Minute, opt.TTL)
}
