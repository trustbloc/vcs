/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fositemongo

import (
	"context"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

func TestCreateSessionWithoutClient(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, mongoErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, mongoErr)

	s, err := NewStore(context.Background(), client)
	assert.NoError(t, err)

	assert.NoError(t, s.createSession(context.TODO(), clientsCollection, "123", &fosite.Request{
		ID: uuid.New(),
		Client: &Client{
			ID: uuid.New(),
		},
		RequestedScope:    []string{"scope1"},
		GrantedScope:      []string{"scope1"},
		RequestedAudience: []string{"aud1"},
		GrantedAudience:   []string{"aud2"},
		Lang:              language.Tag{},
		Session:           &fosite.DefaultSession{},
	}, 0))

	resp, err := s.getSession(context.TODO(), clientsCollection, "123", &fosite.DefaultSession{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrDataNotFound)
}

func TestCreateSessionWithAccessRequest(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, mongoErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, mongoErr)

	s, err := NewStore(context.Background(), client)
	assert.NoError(t, err)

	assert.NoError(t, s.createSession(context.TODO(), clientsCollection, "123", &fosite.AccessRequest{
		Request: fosite.Request{
			ID: uuid.New(),
			Client: &Client{
				ID: uuid.New(),
			},
			RequestedScope:    []string{"scope1"},
			GrantedScope:      []string{"scope1"},
			RequestedAudience: []string{"aud1"},
			GrantedAudience:   []string{"aud2"},
			Lang:              language.Tag{},
			Session:           &fosite.DefaultSession{},
		},
	}, 0))

	resp, err := s.getSession(context.TODO(), clientsCollection, "123", &fosite.DefaultSession{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrDataNotFound)
}

func TestCreateSessionWithoutMongoErr(t *testing.T) {
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

	resp, err := s.getSession(ctx, clientsCollection, "123", &fosite.DefaultSession{})
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "context canceled")
}

func TestCreateExpiredSession(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, mongoErr := mongodb.New(mongoDBConnString, "testdb", mongodb.WithTimeout(time.Second*10))
	assert.NoError(t, mongoErr)

	dbClient := &Client{
		ID: uuid.New(),
	}

	s, err := NewStore(context.Background(), client)
	assert.NoError(t, err)

	_, err = s.InsertClient(context.Background(), *dbClient)
	assert.NoError(t, err)

	assert.NoError(t, s.createSession(context.TODO(), clientsCollection, "123", &fosite.Request{
		ID: uuid.New(),
		Client: &Client{
			ID: uuid.New(),
		},
		RequestedScope:    []string{"scope1"},
		GrantedScope:      []string{"scope1"},
		RequestedAudience: []string{"aud1"},
		GrantedAudience:   []string{"aud2"},
		Lang:              language.Tag{},
		Session:           &fosite.DefaultSession{},
	}, 1))

	resp, err := s.getSession(context.TODO(), clientsCollection, "123", &fosite.DefaultSession{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrDataNotFound)
}
