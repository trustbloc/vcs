/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4cinoncestore

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
	keyPrefix             = "oidc4vcnoncestore"
	intermediateKeyPrefix = keyPrefix + "-" + "intermediate"
)

// Store stores oidc transactions in redis.
type Store struct {
	ttl         time.Duration
	redisClient *redis.Client
}

// New creates Store.
func New(redisClient *redis.Client, ttlSec int32) *Store {
	return &Store{
		redisClient: redisClient,
		ttl:         time.Duration(ttlSec) * time.Second,
	}
}

func (s *Store) Create(
	ctx context.Context,
	transactionData *oidc4ci.TransactionData,
	params ...func(insertOptions *oidc4ci.InsertOptions),
) (*oidc4ci.Transaction, error) {
	// Check opStatueBasedKey key existence.
	opStatueBasedKey := resolveRedisKey(keyPrefix, transactionData.OpState)
	b, err := s.redisClient.API().Exists(ctx, opStatueBasedKey).Result()
	if err != nil {
		return nil, fmt.Errorf("exist: %w", err)
	}

	if b > 0 {
		return nil, oidc4ci.ErrDataNotFound
	}

	insertCfg := &oidc4ci.InsertOptions{}
	for _, p := range params {
		p(insertCfg)
	}

	ttl := s.ttl
	if insertCfg.TTL != 0 {
		ttl = insertCfg.TTL
	}

	transactionID := uuid.NewString()

	doc := &redisDocument{
		ID:              transactionID,
		ExpireAt:        time.Now().UTC().Add(ttl),
		TransactionData: transactionData,
	}

	transactionIDBasedKey := resolveRedisKey(keyPrefix, transactionID)
	intermediateKey := resolveRedisKey(intermediateKeyPrefix, uuid.NewString())

	pipeline := s.redisClient.API().TxPipeline()
	// Set transactionIDBasedKey that points to intermediateKey
	pipeline.Set(ctx, transactionIDBasedKey, intermediateKey, ttl)
	// Set opStatueBasedKey that points to intermediateKey
	pipeline.Set(ctx, opStatueBasedKey, intermediateKey, ttl)
	// Set intermediateKey that points to redisDocument
	pipeline.Set(ctx, intermediateKey, doc, ttl)

	if _, err = pipeline.Exec(ctx); err != nil {
		return nil, fmt.Errorf("transactionData create: %w", err)
	}

	return &oidc4ci.Transaction{
		ID:              oidc4ci.TxID(transactionID),
		TransactionData: *transactionData,
	}, nil
}

func (s *Store) Get(
	ctx context.Context,
	txID oidc4ci.TxID,
) (*oidc4ci.Transaction, error) {
	transactionIDBasedKey := resolveRedisKey(keyPrefix, string(txID))

	intermediateKey, err := s.redisClient.API().Get(ctx, transactionIDBasedKey).Result()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return nil, oidc4ci.ErrDataNotFound
		}

		return nil, err
	}

	return s.findOne(ctx, intermediateKey)
}

func (s *Store) FindByOpState(ctx context.Context, opState string) (*oidc4ci.Transaction, error) {
	return s.Get(ctx, oidc4ci.TxID(opState))
}

func (s *Store) findOne(ctx context.Context, intermediateKey string) (*oidc4ci.Transaction, error) {
	clientAPI := s.redisClient.API()
	b, err := clientAPI.Get(ctx, intermediateKey).Bytes()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return nil, oidc4ci.ErrDataNotFound
		}

		return nil, fmt.Errorf("findOne %w", err)
	}

	var doc redisDocument
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("findOne and decode: %w", err)
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		return nil, oidc4ci.ErrDataNotFound
	}

	return &oidc4ci.Transaction{
		ID:              oidc4ci.TxID(doc.ID),
		TransactionData: *doc.TransactionData,
	}, nil
}

func (s *Store) Update(ctx context.Context, tx *oidc4ci.Transaction) error {
	transactionIDBasedKey := resolveRedisKey(keyPrefix, string(tx.ID))
	opStatueBasedKey := resolveRedisKey(keyPrefix, tx.OpState)

	intermediateKey, err := s.redisClient.API().Get(ctx, transactionIDBasedKey).Result()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return oidc4ci.ErrDataNotFound
		}

		return err
	}

	doc := &redisDocument{
		ID:              string(tx.ID),
		ExpireAt:        time.Now().UTC().Add(s.ttl),
		TransactionData: &tx.TransactionData,
	}

	pipeline := s.redisClient.API().TxPipeline()
	// Set transactionIDBasedKey that points to intermediateKey
	pipeline.Set(ctx, transactionIDBasedKey, intermediateKey, s.ttl)
	// Set opStatueBasedKey that points to intermediateKey
	pipeline.Set(ctx, opStatueBasedKey, intermediateKey, s.ttl)
	// Set intermediateKey that points to redisDocument
	pipeline.Set(ctx, intermediateKey, doc, s.ttl)

	if _, err = pipeline.Exec(ctx); err != nil {
		return fmt.Errorf("transactionData Update: %w", err)
	}

	return nil
}

func resolveRedisKey(prefix, id string) string {
	return fmt.Sprintf("%s-%s", prefix, id)
}
