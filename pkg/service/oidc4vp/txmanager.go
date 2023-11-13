/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination txmanager_mocks_test.go -self_package mocks -package oidc4vp_test -source=txmanager.go -mock_names txStore=MockTxStore,txNonceStore=MockTxNonceStore,txClaimsStore=MockTxClaimsStore,dataProtector=MockDataProtector

package oidc4vp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/dataprotect"
)

const (
	nonceSize  = 10
	maxRetries = 10
)

type TxID string

type Transaction struct {
	ID                     TxID
	ProfileID              string
	ProfileVersion         string
	PresentationDefinition *presexch.PresentationDefinition
	ReceivedClaims         *ReceivedClaims
	ReceivedClaimsID       string
	CustomScopes           []string
}

type ReceivedClaims struct {
	CustomScopeClaims map[string]Claims
	Credentials       map[string]*verifiable.Credential
}

// ReceivedClaimsRaw is temporary struct for parsing to ReceivedClaims, as we need to unmarshal credentials separately.
type ReceivedClaimsRaw struct {
	Credentials       map[string][]byte `json:"credentials"`
	CustomScopeClaims map[string][]byte `json:"customScopeClaims,omitempty"`
}

type ClaimData struct {
	EncryptedData *dataprotect.EncryptedData `json:"encrypted_data"`
}

type TransactionUpdate struct {
	ID               TxID
	ReceivedClaimsID string
}

type txStore interface {
	Create(
		pd *presexch.PresentationDefinition,
		profileID, profileVersion string,
		customScopes []string,
	) (TxID, *Transaction, error)
	Update(update TransactionUpdate) error
	Get(txID TxID) (*Transaction, error)
}

type txClaimsStore interface {
	Create(claims *ClaimData) (string, error)
	Get(claimsID string) (*ClaimData, error)
	Delete(claimsID string) error
}

type txNonceStore interface {
	SetIfNotExist(nonce string, txID TxID) (bool, error)
	GetAndDelete(nonce string) (TxID, bool, error)
}

type dataProtector interface {
	Encrypt(ctx context.Context, msg []byte) (*dataprotect.EncryptedData, error)
	Decrypt(ctx context.Context, encryptedData *dataprotect.EncryptedData) ([]byte, error)
}

// TxManager used to manage oidc transactions.
type TxManager struct {
	nonceStore    txNonceStore
	txStore       txStore
	txClaimsStore txClaimsStore
	dataProtector dataProtector
	docLoader     ld.DocumentLoader
}

// NewTxManager creates TxManager.
func NewTxManager(
	store txNonceStore,
	txStore txStore,
	txClaimsStore txClaimsStore,
	dataProtector dataProtector,
	docLoader ld.DocumentLoader,
) *TxManager {
	return &TxManager{
		nonceStore:    store,
		txStore:       txStore,
		txClaimsStore: txClaimsStore,
		dataProtector: dataProtector,
		docLoader:     docLoader,
	}
}

// CreateTx creates transaction and generate one time access token.
func (tm *TxManager) CreateTx(
	pd *presexch.PresentationDefinition,
	profileID, profileVersion string,
	customScopes []string,
) (*Transaction, string, error) {
	txID, tx, err := tm.txStore.Create(pd, profileID, profileVersion, customScopes)
	if err != nil {
		return nil, "", fmt.Errorf("oidc tx create failed: %w", err)
	}

	nonce, err := tm.tryCreateTxNonce(txID)
	if err != nil {
		return nil, "", fmt.Errorf("oidc tx nonce create failed: %w", err)
	}

	return tx, nonce, nil
}

func (tm *TxManager) DeleteReceivedClaims(claimsID string) error {
	return tm.txClaimsStore.Delete(claimsID)
}

func (tm *TxManager) StoreReceivedClaims(txID TxID, claims *ReceivedClaims) error {
	encrypted, err := tm.EncryptClaims(context.TODO(), claims)
	if err != nil {
		return err
	}

	receivedClaimsID, err := tm.txClaimsStore.Create(encrypted)
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
	decrypted, err := tm.DecryptClaims(context.TODO(), receivedClaims)
	if err != nil {
		return nil, err
	}

	tx.ReceivedClaims = decrypted

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

		isSet, err := tm.nonceStore.SetIfNotExist(nonce, txID)
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
