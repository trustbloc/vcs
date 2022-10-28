/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

func TestBoostrapOidc(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	assert.NoError(t, err)

	secret := uuid.NewString()

	provider, err := bootstrapOAuthProvider(context.TODO(), secret, client)
	assert.NoError(t, err)
	assert.NotNil(t, provider)
}

func TestBoostrapWithInvalidSecret(t *testing.T) {
	provider, err := bootstrapOAuthProvider(context.TODO(), "", nil)
	assert.Nil(t, provider)
	assert.ErrorContains(t, err, "invalid secret")
}

func TestBoostrapOidcWithExpiredContext(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	assert.NoError(t, err)

	secret := uuid.NewString()

	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	provider, err := bootstrapOAuthProvider(ctx, secret, client)

	assert.Nil(t, provider)
	assert.ErrorContains(t, err, "context canceled")
}
