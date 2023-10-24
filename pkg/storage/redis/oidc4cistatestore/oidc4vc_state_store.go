/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cistatestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	redisapi "github.com/redis/go-redis/v9"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	keyPrefix = "oidc4authstate"
)

// Store stores OIDC4CI authorize request/response state in redis.
type Store struct {
	ttl         time.Duration
	redisClient *redis.Client
}

// New creates a new instance of Store.
func New(redisClient *redis.Client, ttlSec int32) *Store {
	return &Store{
		redisClient: redisClient,
		ttl:         time.Duration(ttlSec) * time.Second,
	}
}

func (s *Store) SaveAuthorizeState(
	ctx context.Context,
	opState string,
	data *oidc4ci.AuthorizeState,
	params ...func(insertOptions *oidc4ci.InsertOptions),
) error {
	insertCfg := &oidc4ci.InsertOptions{}
	for _, p := range params {
		p(insertCfg)
	}

	ttl := s.ttl
	if insertCfg.TTL != 0 {
		ttl = insertCfg.TTL
	}

	doc := &redisDocument{
		ExpireAt: time.Now().UTC().Add(ttl),
		State:    data,
	}

	key := resolveRedisKey(opState)
	clientAPI := s.redisClient.API()

	b, err := clientAPI.Exists(ctx, key).Result()
	if err != nil {
		return resterr.NewSystemError(resterr.RedisComponent, "Exists", fmt.Errorf("exists: %w", err))
	}

	if b > 0 {
		return resterr.NewCustomError(resterr.OpStateKeyDuplication, resterr.ErrOpStateKeyDuplication)
	}

	if err = clientAPI.Set(ctx, key, doc, ttl).Err(); err != nil {
		return resterr.NewSystemError(resterr.RedisComponent, "Set", fmt.Errorf("saveAuthorizeState failed: %w", err))
	}

	return nil
}

func (s *Store) GetAuthorizeState(ctx context.Context, opState string) (*oidc4ci.AuthorizeState, error) {
	key := resolveRedisKey(opState)

	b, err := s.redisClient.API().Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return nil, resterr.NewCustomError(resterr.DataNotFound, resterr.ErrDataNotFound)
		}

		return nil, fmt.Errorf("find: %w", err)
	}

	var doc redisDocument
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("claim data decode: %w", err)
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		return nil, resterr.NewCustomError(resterr.DataNotFound, resterr.ErrDataNotFound)
	}

	return doc.State, nil
}

func resolveRedisKey(id string) string {
	return fmt.Sprintf("%s-%s", keyPrefix, id)
}
