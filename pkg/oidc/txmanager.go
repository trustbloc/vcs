/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination txmanager_mocks_test.go -self_package mocks -package oidc_test -source=txmanager.go -mock_names txStore=MockTxStore

package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	nonceSize  = 10
	maxRetries = 10
)

type txStore interface {
	SetIfNotExist(key string, value []byte, expiration time.Duration) (bool, error)
	GetAndDelete(key string) ([]byte, bool, error)
}

// TxManager used to manage oidc transactions.
type TxManager[T any] struct {
	store      txStore       //nolint:structcheck
	txLiveTime time.Duration //nolint:structcheck
}

// NewTxManager creates TxManager.
func NewTxManager[T any](store txStore, txTTL time.Duration) *TxManager[T] {
	return &TxManager[T]{
		store:      store,
		txLiveTime: txTTL,
	}
}

// CreateTx creates transaction and generate one time access token.
func (tm *TxManager[T]) CreateTx(clientID string, tx *T) (string, error) {
	return tm.tryCreateTx(clientID, tx)
}

// GetByOneTimeToken get transaction by one time token and then delete transaction.
func (tm *TxManager[T]) GetByOneTimeToken(clientID, nonce string, tx *T) (bool, error) {
	txBytes, exists, err := tm.store.GetAndDelete(getFullKey(clientID, nonce))
	if err != nil {
		return false, fmt.Errorf("oidc tx store get failed: %w", err)
	}

	if exists {
		err = json.Unmarshal(txBytes, tx)
		if err != nil {
			return exists, fmt.Errorf("tx unmarshal failed: %w", err)
		}
	}

	return exists, nil
}

func (tm *TxManager[T]) tryCreateTx(clientID string, tx *T) (string, error) {
	txBytes, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("tx marshal failed: %w", err)
	}

	for i := 1; i <= maxRetries; i++ {
		nonce, err := genNonce()
		if err != nil {
			return "", err
		}

		isSet, err := tm.store.SetIfNotExist(getFullKey(clientID, nonce), txBytes, tm.txLiveTime)
		if err != nil {
			return "", fmt.Errorf("oidc tx store set failed: %w", err)
		}
		if isSet {
			return nonce, nil
		}
	}

	return "", fmt.Errorf("fail to set tx to store after %d retries", maxRetries)
}

func getFullKey(clientID, nonce string) string {
	return clientID + "-" + nonce
}

func genNonce() (string, error) {
	nonceBytes := make([]byte, nonceSize)

	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("nonce generating random failed: %w", err)
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}
