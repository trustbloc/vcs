/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vptxstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	jsonld "github.com/piprate/json-gold/ld"
	redisapi "github.com/redis/go-redis/v9"
	"github.com/trustbloc/vc-go/presexch"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	keyPrefix = "oidc4vp_tx"
)

// TxStore manages profile in redis.
type TxStore struct {
	defaultTTL     time.Duration
	redisClient    *redis.Client
	documentLoader jsonld.DocumentLoader
}

// NewTxStore creates TxStore.
func NewTxStore(
	redisClient *redis.Client,
	documentLoader jsonld.DocumentLoader,
	vpTransactionDataTTLSec int32) *TxStore {
	return &TxStore{
		defaultTTL:     time.Duration(vpTransactionDataTTLSec) * time.Second,
		redisClient:    redisClient,
		documentLoader: documentLoader,
	}
}

// Create creates transaction document in a database.
func (p *TxStore) Create(
	pd *presexch.PresentationDefinition,
	profileID, profileVersion string,
	profileTransactionDataTTL int32,
	customScopes []string,
) (oidc4vp.TxID, *oidc4vp.Transaction, error) {
	ttl := p.defaultTTL
	if profileTransactionDataTTL > 0 {
		ttl = time.Duration(profileTransactionDataTTL) * time.Second
	}

	ctxWithTimeout, cancel := p.redisClient.ContextWithTimeout()
	defer cancel()

	txDoc := &txDocument{
		ExpireAt:               time.Now().Add(ttl),
		ProfileID:              profileID,
		ProfileVersion:         profileVersion,
		PresentationDefinition: pd,
		CustomScopes:           customScopes,
	}

	txID := uuid.NewString()
	key := resolveRedisKey(txID)

	if err := p.redisClient.API().Set(ctxWithTimeout, key, txDoc, ttl).Err(); err != nil {
		return "", nil, fmt.Errorf("tx set: %w", err)
	}

	tx := txFromDocument(oidc4vp.TxID(txID), txDoc)

	return oidc4vp.TxID(txID), tx, nil
}

// Get returns oidc4vp.Transaction by given id.
func (p *TxStore) Get(strID oidc4vp.TxID) (*oidc4vp.Transaction, error) {
	ctxWithTimeout, cancel := p.redisClient.ContextWithTimeout()
	defer cancel()

	doc, err := p.getTxDocument(ctxWithTimeout, strID)
	if err != nil {
		return nil, err
	}

	return txFromDocument(strID, doc), nil
}

// Delete deletes oidc4vp.Transaction from store.
func (p *TxStore) Delete(strID oidc4vp.TxID) error {
	ctxWithTimeout, cancel := p.redisClient.ContextWithTimeout()
	defer cancel()

	key := resolveRedisKey(string(strID))

	err := p.redisClient.API().Del(ctxWithTimeout, key).Err()
	if err != nil {
		return fmt.Errorf("delete tx %w", err)
	}

	return nil
}

// Get returns txDocument by given id.
func (p *TxStore) getTxDocument(ctx context.Context, strID oidc4vp.TxID) (*txDocument, error) {
	key := resolveRedisKey(string(strID))

	b, err := p.redisClient.API().Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return nil, oidc4vp.ErrDataNotFound
		}

		return nil, fmt.Errorf("find tx %w", err)
	}

	txDoc := &txDocument{}
	if err = json.Unmarshal(b, &txDoc); err != nil {
		return nil, fmt.Errorf("get and decode: %w", err)
	}

	if txDoc.ExpireAt.Before(time.Now().UTC()) {
		return nil, oidc4vp.ErrDataNotFound
	}

	return txDoc, nil
}

func (p *TxStore) Update(update oidc4vp.TransactionUpdate, profileTransactionDataTTL int32) error {
	ttl := p.defaultTTL
	if profileTransactionDataTTL > 0 {
		ttl = time.Duration(profileTransactionDataTTL) * time.Second
	}

	ctxWithTimeout, cancel := p.redisClient.ContextWithTimeout()
	defer cancel()

	txDoc, err := p.getTxDocument(ctxWithTimeout, update.ID)
	if err != nil {
		return err
	}

	txDoc.ReceivedClaimsID = update.ReceivedClaimsID

	key := resolveRedisKey(string(update.ID))

	if err = p.redisClient.API().Set(ctxWithTimeout, key, txDoc, ttl).Err(); err != nil {
		return fmt.Errorf("tx update: %w", err)
	}

	return nil
}

func txFromDocument(id oidc4vp.TxID, txDoc *txDocument) *oidc4vp.Transaction {
	return &oidc4vp.Transaction{
		ID:                     id,
		ProfileID:              txDoc.ProfileID,
		ProfileVersion:         txDoc.ProfileVersion,
		PresentationDefinition: txDoc.PresentationDefinition,
		ReceivedClaimsID:       txDoc.ReceivedClaimsID,
		CustomScopes:           txDoc.CustomScopes,
	}
}

func resolveRedisKey(id string) string {
	return fmt.Sprintf("%s-%s", keyPrefix, id)
}
