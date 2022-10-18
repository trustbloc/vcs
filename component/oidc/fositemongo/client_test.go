package fositemongo

import (
	"context"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

func TestClientAsserting(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, mongoErr := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	assert.NoError(t, mongoErr)

	s, err := NewStore(context.Background(), client)
	assert.NoError(t, err)

	err = s.ClientAssertionJWTValid(context.Background(), "total_random")
	assert.NoError(t, err)
}

func TestClientAssertingWithExpiration(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	testCases := []struct {
		jti string
		exp time.Time
		err error
	}{
		{
			jti: "12345",
			exp: time.Now().UTC().Add(-10 * time.Hour),
			err: nil,
		},
		{
			jti: "111",
			exp: time.Now().UTC().Add(10 * time.Hour),
			err: fosite.ErrJTIKnown,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.jti, func(t *testing.T) {
			client, mongoErr := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
			assert.NoError(t, mongoErr)

			s, err := NewStore(context.Background(), client)
			assert.NoError(t, err)

			assert.NoError(t, s.SetClientAssertionJWT(context.Background(), testCase.jti, testCase.exp))
			err = s.ClientAssertionJWTValid(context.Background(), testCase.jti)
			assert.Equal(t, testCase.err, err)
		})
	}
}
