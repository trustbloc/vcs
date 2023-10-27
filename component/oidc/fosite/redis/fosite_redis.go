/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination client_mocks_test.go -package redis -source=fosite_redis.go -mock_names mockClientManager=MockClientManager

package redis

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"

	"github.com/trustbloc/vcs/pkg/storage/redis"
)

var (
	_ fosite.Storage                = (*Store)(nil)
	_ fosite.PARStorage             = (*Store)(nil)
	_ pkce.PKCERequestStorage       = (*Store)(nil)
	_ oauth2.CoreStorage            = (*Store)(nil)
	_ oauth2.TokenRevocationStorage = (*Store)(nil)
)

const defaultTTL = 24 * time.Hour

type mockClientManager interface { //nolint:unused // used to generate mock
	fosite.ClientManager
}

type Store struct {
	redisClient   *redis.Client
	clientManager fosite.ClientManager
}

func NewStore(client *redis.Client, clientManager fosite.ClientManager) *Store {
	return &Store{
		redisClient:   client,
		clientManager: clientManager,
	}
}
