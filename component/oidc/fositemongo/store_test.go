/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fositemongo

import (
	"context"
	"testing"
	"time"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

func TestStoreFail(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, mongoErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, mongoErr)

	s, err := NewStore(context.Background(), client)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	_, err = s.InsertClient(ctx, Client{
		ID:     uuid.New(),
		Scopes: []string{"awesome"},
	})

	assert.ErrorContains(t, err, "context canceled")
}
