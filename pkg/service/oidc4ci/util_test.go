package oidc4ci_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestWithTtl(t *testing.T) {
	opt := &oidc4ci.InsertOptions{}
	oidc4ci.WithDocumentTTL(10 * time.Minute)(opt)
	assert.Equal(t, 10*time.Minute, opt.TTL)
}
