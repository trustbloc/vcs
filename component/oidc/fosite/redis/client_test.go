/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

func TestClientManagerInterface(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	redisClient, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	ctx := context.Background()

	t.Run("GetClient", func(t *testing.T) {
		clientManager := NewMockClientManager(gomock.NewController(t))
		clientManager.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(1).Return(&oauth2client.Client{}, nil)

		store := NewStore(redisClient, clientManager)

		_, err = store.GetClient(ctx, "clientID")
		assert.NoError(t, err)
	})

	t.Run("ClientAssertionJWTValid", func(t *testing.T) {
		clientManager := NewMockClientManager(gomock.NewController(t))
		clientManager.EXPECT().ClientAssertionJWTValid(gomock.Any(), gomock.Any()).Times(1)

		store := NewStore(redisClient, clientManager)

		err = store.ClientAssertionJWTValid(ctx, "jti")
		assert.NoError(t, err)
	})

	t.Run("SetClientAssertionJWT", func(t *testing.T) {
		clientManager := NewMockClientManager(gomock.NewController(t))
		clientManager.EXPECT().SetClientAssertionJWT(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

		store := NewStore(redisClient, clientManager)

		err = store.SetClientAssertionJWT(ctx, "jti", time.Now().UTC())
		assert.NoError(t, err)
	})
}
