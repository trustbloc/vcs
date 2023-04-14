/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/storage/redis"
)

func TestClientAsserting(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	s := NewStore(client)

	err = s.ClientAssertionJWTValid(context.Background(), "total_random")
	assert.NoError(t, err)
}

func TestReturnNonNilClient(t *testing.T) {
	cl, err := (&Store{}).GetClient(context.TODO(), "")
	assert.NoError(t, err)
	assert.Equal(t, fosite.DefaultClient{}, *(cl.(*fosite.DefaultClient)))
}

func TestClientAssertingWithExpiration(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	s := NewStore(client)

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
			assert.NoError(t, s.SetClientAssertionJWT(context.Background(), testCase.jti, testCase.exp))
			err := s.ClientAssertionJWTValid(context.Background(), testCase.jti)
			assert.Equal(t, testCase.err, err)
		})
	}
}
