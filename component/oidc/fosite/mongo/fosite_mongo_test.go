/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

func TestFailMigration(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, mongoErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, mongoErr)

	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	s, err := NewStore(ctx, client)
	assert.Nil(t, s)
	assert.ErrorContains(t, err, "context canceled")
}
