/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination txmanager_mocks_test.go -self_package mocks -package oidc4vp_test -source=txmanager.go -mock_names txStore=MockTxStore,txNonceStore=MockTxNonceStore,txClaimsStore=MockTxClaimsStore

package oidc4vp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

const (
	nonceSize  = 10
	maxRetries = 10
)

type TxID string

type Transaction struct {
	ID                     TxID
	ProfileID              string
	PresentationDefinition *presexch.PresentationDefinition
	ReceivedClaims         *ReceivedClaims
	ReceivedClaimsID       string
}

type ReceivedClaims struct {
	Credentials map[string]*verifiable.Credential `json:"credentials"`
}

type TransactionUpdate struct {
	ID               TxID
	ReceivedClaimsID string
}

type txStore interface {
	Create(pd *presexch.PresentationDefinition, profileID string) (TxID, *Transaction, error)
	Update(update TransactionUpdate) error
	Get(txID TxID) (*Transaction, error)
}

type txClaimsStore interface {
	Create(claims *ReceivedClaims) (string, error)
	Get(claimsID string) (*ReceivedClaims, error)
}

type txNonceStore interface {
	SetIfNotExist(nonce string, txID TxID, expiration time.Duration) (bool, error)
	GetAndDelete(nonce string) (TxID, bool, error)
}

// TxManager used to manage oidc transactions.
type TxManager struct {
	nonceStore          txNonceStore
	txStore             txStore
	txClaimsStore       txClaimsStore
	interactionLiveTime time.Duration
}

// NewTxManager creates TxManager.
func NewTxManager(store txNonceStore, txStore txStore, txClaimsStore txClaimsStore, interactionLiveTime time.Duration) *TxManager { //nolint:lll
	return &TxManager{
		nonceStore:          store,
		txStore:             txStore,
		txClaimsStore:       txClaimsStore,
		interactionLiveTime: interactionLiveTime,
	}
}

// CreateTx creates transaction and generate one time access token.
func (tm *TxManager) CreateTx(pd *presexch.PresentationDefinition, profileID string) (*Transaction, string, error) {
	txID, tx, err := tm.txStore.Create(pd, profileID)
	if err != nil {
		return nil, "", fmt.Errorf("oidc tx create failed: %w", err)
	}

	nonce, err := tm.tryCreateTxNonce(txID)
	if err != nil {
		return nil, "", fmt.Errorf("oidc tx nonce create failed: %w", err)
	}

	return tx, nonce, nil
}

func (tm *TxManager) StoreReceivedClaims(txID TxID, claims *ReceivedClaims) error {
	receivedClaimsID, err := tm.txClaimsStore.Create(claims)
	if err != nil {
		return err
	}

	return tm.txStore.Update(TransactionUpdate{ID: txID, ReceivedClaimsID: receivedClaimsID})
}

// Get transaction id.
func (tm *TxManager) Get(txID TxID) (*Transaction, error) {
	tx, err := tm.txStore.Get(txID)
	if errors.Is(err, ErrDataNotFound) {
		return nil, err
	}

	if err != nil {
		return nil, fmt.Errorf("oidc get tx by id failed: %w", err)
	}

	if tx.ReceivedClaimsID == "" {
		return tx, nil
	}

	receivedClaims, err := tm.txClaimsStore.Get(tx.ReceivedClaimsID)
	if err != nil && !errors.Is(err, ErrDataNotFound) {
		return nil, fmt.Errorf("find received claims: %w", err)
	}

	tx.ReceivedClaims = receivedClaims

	return tx, nil
}

// GetByOneTimeToken get transaction by nonce and then delete nonce.
func (tm *TxManager) GetByOneTimeToken(nonce string) (*Transaction, bool, error) {
	txID, valid, err := tm.nonceStore.GetAndDelete(nonce)
	if err != nil {
		return nil, false, fmt.Errorf("oidc tx nonceStore get failed: %w", err)
	}

	var tx *Transaction
	if valid {
		tx, err = tm.txStore.Get(txID)
		if err != nil {
			return nil, false, fmt.Errorf("oidc get tx by id failed: %w", err)
		}
	}

	return tx, valid, nil
}

func (tm *TxManager) tryCreateTxNonce(txID TxID) (string, error) {
	for i := 1; i <= maxRetries; i++ {
		nonce, err := genNonce()
		if err != nil {
			return "", err
		}

		isSet, err := tm.nonceStore.SetIfNotExist(nonce, txID, tm.interactionLiveTime)
		if err != nil {
			return "", fmt.Errorf("oidc tx nonceStore set failed: %w", err)
		}
		if isSet {
			return nonce, nil
		}
	}

	return "", fmt.Errorf("fail to set tx to nonceStore after %d retries", maxRetries)
}

func genNonce() (string, error) {
	nonceBytes := make([]byte, nonceSize)

	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("nonce generating random failed: %w", err)
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}
