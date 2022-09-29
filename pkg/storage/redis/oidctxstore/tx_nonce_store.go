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

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

// TxNonceStore stores oidc transactions in redis.
type TxNonceStore struct {
	client    *redis.Client
	opTimeout time.Duration
}

// New creates TxNonceStore.
func New(client *redis.Client, opTimeout time.Duration) *TxNonceStore {
	return &TxNonceStore{
		client:    client,
		opTimeout: opTimeout,
	}
}

// GetAndDelete get and then delete transaction by one time token.
func (ts *TxNonceStore) GetAndDelete(nonce string) (string, bool, error) {
	ctxWithTimeout, cancel := ts.contextWithTimeout()
	defer cancel()

	value, err := ts.client.GetDel(ctxWithTimeout, nonce).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("redis getdel failed: %w", err)
	}

	return value, true, nil
}

// SetIfNotExist stores transaction if key not exists et.
func (ts *TxNonceStore) SetIfNotExist(nonce string, txID oidc4vp.TxID, expiration time.Duration) (bool, error) {
	ctxWithTimeout, cancel := ts.contextWithTimeout()
	defer cancel()

	isSet, err := ts.client.SetNX(ctxWithTimeout, nonce, string(txID), expiration).Result()
	if err != nil {
		return false, fmt.Errorf("redis setnx failed: %w", err)
	}

	return isSet, nil
}

func (ts *TxNonceStore) contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), ts.opTimeout)
}
