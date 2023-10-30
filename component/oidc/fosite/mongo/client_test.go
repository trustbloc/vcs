/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

func TestClientManagerInterface(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	mongoClient, mongoErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, mongoErr)

	ctx := context.Background()

	t.Run("GetClient", func(t *testing.T) {
		clientManager := NewMockClientManager(gomock.NewController(t))
		clientManager.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(1).Return(&oauth2client.Client{}, nil)

		store, err := NewStore(ctx, mongoClient, clientManager)
		assert.NoError(t, err)

		_, err = store.GetClient(ctx, "clientID")
		assert.NoError(t, err)
	})

	t.Run("ClientAssertionJWTValid", func(t *testing.T) {
		clientManager := NewMockClientManager(gomock.NewController(t))
		clientManager.EXPECT().ClientAssertionJWTValid(gomock.Any(), gomock.Any()).Times(1)

		store, err := NewStore(ctx, mongoClient, clientManager)
		assert.NoError(t, err)

		err = store.ClientAssertionJWTValid(ctx, "jti")
		assert.NoError(t, err)
	})

	t.Run("SetClientAssertionJWT", func(t *testing.T) {
		clientManager := NewMockClientManager(gomock.NewController(t))
		clientManager.EXPECT().SetClientAssertionJWT(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

		store, err := NewStore(ctx, mongoClient, clientManager)
		assert.NoError(t, err)

		err = store.SetClientAssertionJWT(ctx, "jti", time.Now().UTC())
		assert.NoError(t, err)
	})
}
