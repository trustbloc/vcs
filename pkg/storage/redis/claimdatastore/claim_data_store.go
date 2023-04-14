/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package claimdatastore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	redisapi "github.com/redis/go-redis/v9"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	keyPrefix = "oidc4vcclaims"
)

// Store stores claim data with expiration.
type Store struct {
	redisClient *redis.Client
	ttl         time.Duration
}

// New creates a new instance of Store.
func New(redisClient *redis.Client, ttlSec int32) *Store {
	return &Store{
		redisClient: redisClient,
		ttl:         time.Duration(ttlSec) * time.Second,
	}
}

func (s *Store) Create(ctx context.Context, data *oidc4ci.ClaimData) (string, error) {
	doc := &redisDocument{
		ClaimData: *data,
		ExpireAt:  time.Now().UTC().Add(s.ttl),
	}

	key := resolveRedisKey(uuid.NewString())

	return key, s.redisClient.API().Set(ctx, key, doc, s.ttl).Err()
}

func (s *Store) GetAndDelete(ctx context.Context, claimDataID string) (*oidc4ci.ClaimData, error) {
	clientAPI := s.redisClient.API()
	b, err := clientAPI.Get(ctx, claimDataID).Bytes()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return nil, oidc4ci.ErrDataNotFound
		}

		return nil, fmt.Errorf("find key %w", err)
	}

	if err = clientAPI.Del(ctx, claimDataID).Err(); err != nil {
		return nil, fmt.Errorf("del failed: %w", err)
	}

	var doc redisDocument
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("get and decode: %w", err)
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		return nil, oidc4ci.ErrDataNotFound
	}

	claimData := doc.ClaimData

	return &claimData, nil
}

func resolveRedisKey(id string) string {
	return fmt.Sprintf("%s-%s", keyPrefix, id)
}
