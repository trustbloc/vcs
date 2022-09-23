/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidctxstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// TxStore stores oidc transactions in redis.
type TxStore struct {
	client    *redis.Client
	opTimeout time.Duration
}

// New creates TxStore.
func New(client *redis.Client, opTimeout time.Duration) *TxStore {
	return &TxStore{
		client:    client,
		opTimeout: opTimeout,
	}
}

// GetAndDelete get and then delete transaction by one time token.
func (ts *TxStore) GetAndDelete(key string) ([]byte, bool, error) {
	ctxWithTimeout, cancel := ts.contextWithTimeout()
	defer cancel()

	value, err := ts.client.GetDel(ctxWithTimeout, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("redis getdel failed: %w", err)
	}

	return []byte(value), true, nil
}

// SetIfNotExist stores transaction if key not exists et.
func (ts *TxStore) SetIfNotExist(key string, value []byte, expiration time.Duration) (bool, error) {
	ctxWithTimeout, cancel := ts.contextWithTimeout()
	defer cancel()

	isSet, err := ts.client.SetNX(ctxWithTimeout, key, string(value), expiration).Result()
	if err != nil {
		return false, fmt.Errorf("redis setnx failed: %w", err)
	}

	return isSet, nil
}

func (ts *TxStore) contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), ts.opTimeout)
}
