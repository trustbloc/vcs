/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"testing"

	"github.com/ory/fosite"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/clientmanager"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

func TestCreateSessionWithoutClient(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	clientManager, mongoDBPool, mongoDBResource := createClientManager(t)
	defer func() {
		assert.NoError(t, mongoDBPool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	s := NewStore(client, clientManager)

	assert.NoError(t, s.createSession(context.TODO(), dto.AuthCodeSegment, "123", &fosite.Request{
		ID: uuid.New(),
		Client: &oauth2client.Client{
			ID: uuid.New(),
		},
		RequestedScope:    []string{"scope1"},
		GrantedScope:      []string{"scope1"},
		RequestedAudience: []string{"aud1"},
		GrantedAudience:   []string{"aud2"},
		Lang:              language.Tag{},
		Session:           &fosite.DefaultSession{},
	}, 0))

	resp, err := s.getSession(context.TODO(), dto.AuthCodeSegment, "123", &fosite.DefaultSession{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, clientmanager.ErrDataNotFound)
}

func TestCreateSessionWithAccessRequest(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	clientManager, mongoDBPool, mongoDBResource := createClientManager(t)
	defer func() {
		assert.NoError(t, mongoDBPool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	s := NewStore(client, clientManager)

	assert.NoError(t, s.createSession(context.TODO(), dto.AuthCodeSegment, "123", &fosite.AccessRequest{
		Request: fosite.Request{
			ID: uuid.New(),
			Client: &oauth2client.Client{
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

	resp, err := s.getSession(context.TODO(), dto.AuthCodeSegment, "123", &fosite.DefaultSession{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, clientmanager.ErrDataNotFound)
}

func TestCreateSessionWithoutRedisErr(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	clientManager, mongoDBPool, mongoDBResource := createClientManager(t)
	defer func() {
		assert.NoError(t, mongoDBPool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	s := NewStore(client, clientManager)

	ctx, cancel := context.WithCancel(context.TODO())
	cancel()

	resp, err := s.getSession(ctx, dto.AuthCodeSegment, "123", &fosite.DefaultSession{})
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "context canceled")
}

func TestCreateExpiredSession(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client, err := redis.New([]string{redisConnString})
	assert.NoError(t, err)

	clientManager, mongoDBPool, mongoDBResource := createClientManager(t)
	defer func() {
		assert.NoError(t, mongoDBPool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	s := NewStore(client, clientManager)

	dbClient := &oauth2client.Client{
		ID: uuid.New(),
	}

	_, err = clientManager.InsertClient(context.Background(), dbClient)
	assert.NoError(t, err)

	assert.NoError(t, s.createSession(context.TODO(), dto.AuthCodeSegment, "123", &fosite.Request{
		ID: uuid.New(),
		Client: &oauth2client.Client{
			ID: uuid.New(),
		},
		RequestedScope:    []string{"scope1"},
		GrantedScope:      []string{"scope1"},
		RequestedAudience: []string{"aud1"},
		GrantedAudience:   []string{"aud2"},
		Lang:              language.Tag{},
		Session:           &fosite.DefaultSession{},
	}, 1))

	resp, err := s.getSession(context.TODO(), dto.AuthCodeSegment, "123", &fosite.DefaultSession{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, dto.ErrDataNotFound)
}
