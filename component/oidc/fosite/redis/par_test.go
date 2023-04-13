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
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
)

func TestPar(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client := redis.NewClient(&redis.Options{
		Addr:                  redisConnString,
		ContextTimeoutEnabled: true,
	})

	s := NewStore(client)

	testCases := []struct {
		name      string
		useRevoke bool
	}{
		{
			name:      "use delete",
			useRevoke: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dbClient := &dto.Client{
				ID:     uuid.New(),
				Scopes: []string{"awesome"},
			}

			_, err := s.InsertClient(context.Background(), *dbClient)
			assert.NoError(t, err)

			sign := uuid.New()
			ses := &fosite.AuthorizeRequest{
				ResponseTypes:        []string{"response_type"},
				State:                "213123",
				HandledResponseTypes: nil,
				ResponseMode:         "dsfdsaf",
				DefaultResponseMode:  "gfdsgsfdgdf",
				Request: fosite.Request{
					Client: dbClient,
				},
			}

			err = s.CreatePARSession(context.TODO(), sign, ses)
			assert.NoError(t, err)

			dbSes, err := s.GetPARSession(context.TODO(), sign)
			assert.NoError(t, err)
			assert.Equal(t, ses, dbSes)
			assert.Equal(t, dbClient.ID, dbSes.GetClient().GetID())

			err = s.DeletePARSession(context.TODO(), sign)
			assert.NoError(t, err)
		})
	}
}

func TestParInvalidMapping(t *testing.T) {
	s := Store{}

	type xx struct {
		fosite.AuthorizeRequest
	}

	err := s.CreatePARSession(context.TODO(), "sdfsd", &xx{})
	assert.ErrorContains(t, err, "expected record of type *fosite.AuthorizeRequest")
}

func TestRequestInvalidSession(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client := redis.NewClient(&redis.Options{
		Addr:                  redisConnString,
		ContextTimeoutEnabled: true,
	})

	s := NewStore(client)

	dbSes, err := s.GetPARSession(context.TODO(), "111111")
	assert.Nil(t, dbSes)
	assert.ErrorIs(t, err, dto.ErrDataNotFound)
}

func TestRequestInvalidParSessionWithoutClient(t *testing.T) {
	pool, redisResource := startRedisContainer(t)

	defer func() {
		assert.NoError(t, pool.Purge(redisResource), "failed to purge Redis resource")
	}()

	client := redis.NewClient(&redis.Options{
		Addr:                  redisConnString,
		ContextTimeoutEnabled: true,
	})

	s := NewStore(client)

	dbSes, err := s.GetPARSession(context.TODO(), "111111")
	assert.Nil(t, dbSes)
	assert.ErrorIs(t, err, dto.ErrDataNotFound)

	dbClient := &dto.Client{
		ID:     uuid.New(),
		Scopes: []string{"awesome"},
	}

	sign := uuid.New()
	ses := &fosite.AuthorizeRequest{
		ResponseTypes:        []string{"response_type"},
		State:                "213123",
		HandledResponseTypes: nil,
		ResponseMode:         "dsfdsaf",
		DefaultResponseMode:  "gfdsgsfdgdf",
		Request: fosite.Request{
			Client: dbClient,
		},
	}

	err = s.CreatePARSession(context.TODO(), sign, ses)
	assert.NoError(t, err)

	dbSes, err = s.GetPARSession(context.TODO(), sign)
	assert.Nil(t, dbSes)
	assert.ErrorIs(t, err, dto.ErrDataNotFound)
}
