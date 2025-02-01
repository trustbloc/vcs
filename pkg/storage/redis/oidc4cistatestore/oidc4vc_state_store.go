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

var (
	ErrOpStateKeyDuplication = errors.New("op state key duplication")
)

// Store stores OIDC4CI authorize request/response state in redis.
type Store struct {
	defaultTTL  time.Duration
	redisClient *redis.Client
}

// New creates a new instance of Store.
func New(redisClient *redis.Client, ttlSec int32) *Store {
	return &Store{
		redisClient: redisClient,
		defaultTTL:  time.Duration(ttlSec) * time.Second,
	}
}

func (s *Store) SaveAuthorizeState(
	ctx context.Context,
	profileAuthStateTTL int32,
	opState string,
	data *oidc4ci.AuthorizeState,
) error {
	ttl := s.defaultTTL
	if profileAuthStateTTL != 0 {
		ttl = time.Duration(profileAuthStateTTL) * time.Second
	}

	doc := &redisDocument{
		ExpireAt: time.Now().UTC().Add(ttl),
		State:    data,
	}

	key := resolveRedisKey(opState)
	clientAPI := s.redisClient.API()

	b, err := clientAPI.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("exists: %w", err)
	}

	if b > 0 {
		return ErrOpStateKeyDuplication
	}

	if err = clientAPI.Set(ctx, key, doc, s.defaultTTL).Err(); err != nil {
		return fmt.Errorf("saveAuthorizeState failed: %w", err)
	}

	return nil
}

func (s *Store) GetAuthorizeState(ctx context.Context, opState string) (*oidc4ci.AuthorizeState, error) {
	key := resolveRedisKey(opState)

	b, err := s.redisClient.API().Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return nil, resterr.ErrDataNotFound
		}

		return nil, fmt.Errorf("find: %w", err)
	}

	var doc redisDocument
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("claim data decode: %w", err)
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		return nil, resterr.ErrDataNotFound
	}

	return doc.State, nil
}

func resolveRedisKey(id string) string {
	return fmt.Sprintf("%s-%s", keyPrefix, id)
}
