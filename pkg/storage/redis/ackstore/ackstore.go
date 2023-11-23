/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ackstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	keyPrefix = "oidc4ci_ack"
)

// Store stores claim data with expiration.
type Store struct {
	redisClient redisClient
	ttl         time.Duration
}

// New creates presentation claims store.
func New(redisClient redisClient, ttlSec int32) *Store {
	return &Store{
		redisClient: redisClient,
		ttl:         time.Duration(ttlSec) * time.Second,
	}
}

func (s *Store) Create(
	ctx context.Context,
	ack *oidc4ci.Ack,
) (string, error) {
	id := string(ack.TxID) // for now, it should much with TxID before new spec.

	b, err := json.Marshal(ack)
	if err != nil {
		return "", err
	}

	if err = s.redisClient.API().Set(ctx, s.resolveRedisKey(id), string(b), s.ttl).Err(); err != nil {
		return "", fmt.Errorf("redis insert received claims data: %w", err)
	}

	return id, nil
}

func (s *Store) Get(ctx context.Context, id string) (*oidc4ci.Ack, error) {
	b, err := s.redisClient.API().Get(ctx, s.resolveRedisKey(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, oidc4ci.ErrDataNotFound
		}

		return nil, err
	}

	var doc oidc4ci.Ack
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("data decode: %w", err)
	}

	return &doc, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	err := s.redisClient.API().Del(ctx, s.resolveRedisKey(id)).Err()
	if err != nil {
		return fmt.Errorf("failed to delete ack with id[%s]: %w", id, err)
	}

	return nil
}

func (s *Store) resolveRedisKey(id string) string {
	return fmt.Sprintf("%s-%s", keyPrefix, id)
}
