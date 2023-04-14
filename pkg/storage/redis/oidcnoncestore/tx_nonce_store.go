/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidcnoncestore

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

// TxNonceStore stores oidc transactions in mongo.
type TxNonceStore struct {
	redisClient *redis.Client
}

// New creates TxNonceStore.
func New(redisClient *redis.Client) *TxNonceStore {
	return &TxNonceStore{
		redisClient: redisClient,
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
func (ts *TxNonceStore) SetIfNotExist(nonce string, txID oidc4vp.TxID, expiration time.Duration) (bool, error) {
	ctxWithTimeout, cancel := ts.redisClient.ContextWithTimeout()
	defer cancel()

	clientAPI := ts.redisClient.API()

	doc := &nonceDocument{
		TxID:     txID,
		ExpireAt: time.Now().Add(expiration),
	}

	key := resolveRedisKey(nonce)

	b, err := clientAPI.Exists(ctxWithTimeout, key).Result()
	if err != nil {
		return false, fmt.Errorf("exist: %w", err)
	}

	if b > 0 {
		return false, nil
	}

	if err = clientAPI.Set(ctxWithTimeout, key, doc, expiration).Err(); err != nil {
		return false, fmt.Errorf("tx set: %w", err)
	}

	return true, nil
}

func resolveRedisKey(id string) string {
	return fmt.Sprintf("%s-%s", keyPrefix, id)
}
