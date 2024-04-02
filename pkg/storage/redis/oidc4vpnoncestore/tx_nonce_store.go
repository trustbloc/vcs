/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vpnoncestore

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	redisapi "github.com/redis/go-redis/v9"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	keyPrefix = "oidc4vpnonce"
)

// TxNonceStore stores oidc transactions in redis.
type TxNonceStore struct {
	redisClient *redis.Client
	defaultTTL  time.Duration
}

// New creates TxNonceStore.
func New(redisClient *redis.Client, ttlSec int32) *TxNonceStore {
	return &TxNonceStore{
		redisClient: redisClient,
		defaultTTL:  time.Duration(ttlSec) * time.Second,
	}
}

// GetAndDelete get and then delete transaction by one time token.
func (ts *TxNonceStore) GetAndDelete(nonce string) (oidc4vp.TxID, bool, error) {
	ctxWithTimeout, cancel := ts.redisClient.ContextWithTimeout()
	defer cancel()

	key := resolveRedisKey(nonce)
	clientAPI := ts.redisClient.API()

	b, err := clientAPI.Get(ctxWithTimeout, key).Bytes()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return "", false, nil
		}

		return "", false, fmt.Errorf("tx find failed: %w", err)
	}

	if err = clientAPI.Del(ctxWithTimeout, key).Err(); err != nil {
		return "", false, fmt.Errorf("tx delete failed: %w", err)
	}

	doc := &nonceDocument{}
	if err = json.Unmarshal(b, &doc); err != nil {
		return "", false, fmt.Errorf("tx decode failed: %w", err)
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		return "", false, nil
	}

	return doc.TxID, true, nil
}

// SetIfNotExist stores transaction if key not exists et.
func (ts *TxNonceStore) SetIfNotExist(nonce string, profileNonceStoreDataTTL int32, txID oidc4vp.TxID) (bool, error) {
	ctxWithTimeout, cancel := ts.redisClient.ContextWithTimeout()
	defer cancel()

	clientAPI := ts.redisClient.API()

	ttl := ts.defaultTTL
	if profileNonceStoreDataTTL > 0 {
		ttl = time.Duration(profileNonceStoreDataTTL) * time.Second
	}

	doc := &nonceDocument{
		TxID:     txID,
		ExpireAt: time.Now().Add(ttl),
	}

	key := resolveRedisKey(nonce)

	b, err := clientAPI.Exists(ctxWithTimeout, key).Result()
	if err != nil {
		return false, fmt.Errorf("exist: %w", err)
	}

	if b > 0 {
		return false, nil
	}

	if err = clientAPI.Set(ctxWithTimeout, key, doc, ttl).Err(); err != nil {
		return false, fmt.Errorf("tx set: %w", err)
	}

	return true, nil
}

func resolveRedisKey(id string) string {
	return fmt.Sprintf("%s-%s", keyPrefix, id)
}
