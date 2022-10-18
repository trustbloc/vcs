package fositemongo

import (
	"testing"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
)

func TestClient(t *testing.T) {
	cl := Client{
		ID:             "random_id",
		Secret:         []byte{0x01, 0x02},
		RotatedSecrets: [][]byte{{0x1}},
		RedirectURIs:   []string{"redirect_uri"},
		GrantTypes:     []string{"grand_types"},
		ResponseTypes:  []string{"types"},
		Scopes:         []string{"scope"},
		Audience:       []string{"audience"},
		Public:         true,
	}

	assert.Equal(t, cl.ID, cl.GetID())
	assert.Equal(t, cl.Secret, cl.GetHashedSecret())
	assert.Equal(t, cl.RedirectURIs, cl.GetRedirectURIs())
	assert.Equal(t, cl.RedirectURIs, cl.GetRedirectURIs())
	assert.Equal(t, cl.GetGrantTypes(), cl.GetGrantTypes())
	assert.Equal(t, fosite.Arguments(cl.ResponseTypes), cl.GetResponseTypes())
	assert.Equal(t, fosite.Arguments(cl.Scopes), cl.GetScopes())
	assert.Equal(t, cl.Public, cl.IsPublic())
	assert.Equal(t, fosite.Arguments(cl.Audience), cl.GetAudience())
}

func TestGrantTypes(t *testing.T) {
	cl := Client{}

	assert.Equal(t, fosite.Arguments{"authorization_code"}, cl.GetGrantTypes())
	assert.Equal(t, fosite.Arguments{"code"}, cl.GetResponseTypes())
}
