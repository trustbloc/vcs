/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/ory/fosite"
	"github.com/pborman/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
)

const (
	redisConnString  = "localhost:6379"
	dockerRedisImage = "redis"
	dockerRedisTag   = "alpine3.17"
)

func TestAccessTokenFlow(t *testing.T) {
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
		{
			name:      "use revoke",
			useRevoke: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dbClient := &dto.Client{
				ID:             uuid.New(),
				Secret:         nil,
				RotatedSecrets: nil,
				RedirectURIs:   nil,
				GrantTypes:     nil,
				ResponseTypes:  nil,
				Scopes:         []string{"awesome"},
				Audience:       nil,
				Public:         false,
			}

			_, err := s.InsertClient(context.Background(), *dbClient)
			assert.NoError(t, err)

			sign := uuid.New()
			sesExtra := map[string]interface{}{
				"opState": "2135441",
			}

			ses := &fosite.Request{
				ID:                uuid.New(),
				Client:            dbClient,
				RequestedScope:    []string{"scope1"},
				GrantedScope:      []string{"scope1"},
				RequestedAudience: []string{"aud1"},
				GrantedAudience:   []string{"aud2"},
				Lang:              language.Tag{},
				Session: &fosite.DefaultSession{
					Extra: sesExtra,
				},
			}

			err = s.CreateAccessTokenSession(context.TODO(), sign, ses)
			assert.NoError(t, err)

			dbSes, err := s.GetAccessTokenSession(context.TODO(), sign, new(fosite.DefaultSession))
			assert.NoError(t, err)
			assert.Equal(t, ses, dbSes)
			assert.Equal(t, dbClient.ID, dbSes.GetClient().GetID())
			assert.Equal(t, sesExtra, dbSes.GetSession().(*fosite.DefaultSession).Extra)

			if testCase.useRevoke {
				err = s.RevokeAccessToken(context.TODO(), ses.ID)
				assert.NoError(t, err)
			} else {
				err = s.DeleteAccessTokenSession(context.TODO(), sign)
				assert.NoError(t, err)
			}

			resp, err := s.GetAccessTokenSession(context.TODO(), sign, ses.Session)
			assert.Nil(t, resp)
			assert.ErrorIs(t, err, dto.ErrDataNotFound)
		})
	}
}

func waitForRedisToBeUp() error {
	return backoff.Retry(pingRedis, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingRedis() error {
	rdb := redis.NewClient(&redis.Options{
		Addr: redisConnString,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return rdb.Ping(ctx).Err()
}

func startRedisContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	redisResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerRedisImage,
		Tag:        dockerRedisTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"6379/tcp": {{HostIP: "", HostPort: "6379"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisToBeUp())

	return pool, redisResource
}
