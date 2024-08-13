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

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

const (
	keyPrefix             = "oidc4vcnoncestore"
	intermediateKeyPrefix = keyPrefix + "-" + "intermediate"
)

// Store stores oidc transactions in redis.
type Store struct {
	defaultTTL  time.Duration
	redisClient *redis.Client
}

// New creates Store.
func New(redisClient *redis.Client, ttlSec int32) *Store {
	return &Store{
		redisClient: redisClient,
		defaultTTL:  time.Duration(ttlSec) * time.Second,
	}
}

func (s *Store) ForceCreate(
	ctx context.Context,
	profileTransactionDataTTL int32,
	transactionData *issuecredential.TransactionData,
) (*issuecredential.Transaction, error) {
	return s.createInternal(ctx, profileTransactionDataTTL, transactionData, true)
}

func (s *Store) Create(
	ctx context.Context,
	profileTransactionDataTTL int32,
	transactionData *issuecredential.TransactionData,
) (*issuecredential.Transaction, error) {
	return s.createInternal(ctx, profileTransactionDataTTL, transactionData, false)
}

func (s *Store) createInternal(
	ctx context.Context,
	profileTransactionDataTTL int32,
	transactionData *issuecredential.TransactionData,
	force bool,
) (*issuecredential.Transaction, error) {
	// Check opStatueBasedKey key existence.
	opStatueBasedKey := resolveRedisKey(keyPrefix, transactionData.OpState)
	if !force {
		b, err := s.redisClient.API().Exists(ctx, opStatueBasedKey).Result()
		if err != nil {
			return nil, fmt.Errorf("exist: %w", err)
		}

		if b > 0 {
			return nil, resterr.ErrDataNotFound
		}
	}

	ttl := s.defaultTTL
	if profileTransactionDataTTL != 0 {
		ttl = time.Duration(profileTransactionDataTTL) * time.Second
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

	if _, err := pipeline.Exec(ctx); err != nil {
		return nil, fmt.Errorf("transactionData create: %w", err)
	}

	return &issuecredential.Transaction{
		ID:              issuecredential.TxID(transactionID),
		TransactionData: *transactionData,
	}, nil
}

func (s *Store) Get(
	ctx context.Context,
	txID issuecredential.TxID,
) (*issuecredential.Transaction, error) {
	transactionIDBasedKey := resolveRedisKey(keyPrefix, string(txID))

	intermediateKey, err := s.redisClient.API().Get(ctx, transactionIDBasedKey).Result()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return nil, resterr.ErrDataNotFound
		}

		return nil, err
	}

	return s.findOne(ctx, intermediateKey)
}

func (s *Store) FindByOpState(ctx context.Context, opState string) (*issuecredential.Transaction, error) {
	return s.Get(ctx, issuecredential.TxID(opState))
}

func (s *Store) findOne(ctx context.Context, intermediateKey string) (*issuecredential.Transaction, error) {
	clientAPI := s.redisClient.API()
	b, err := clientAPI.Get(ctx, intermediateKey).Bytes()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return nil, resterr.ErrDataNotFound
		}

		return nil, fmt.Errorf("findOne %w", err)
	}

	var doc redisDocument
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("findOne and decode: %w", err)
	}

	if doc.ExpireAt.Before(time.Now().UTC()) {
		return nil, resterr.ErrDataNotFound
	}

	return &issuecredential.Transaction{
		ID:              issuecredential.TxID(doc.ID),
		TransactionData: *doc.TransactionData,
	}, nil
}

func (s *Store) Update(ctx context.Context, tx *issuecredential.Transaction) error {
	transactionIDBasedKey := resolveRedisKey(keyPrefix, string(tx.ID))
	opStatueBasedKey := resolveRedisKey(keyPrefix, tx.OpState)

	intermediateKey, err := s.redisClient.API().Get(ctx, transactionIDBasedKey).Result()
	if err != nil {
		if errors.Is(err, redisapi.Nil) {
			return resterr.ErrDataNotFound
		}

		return err
	}

	doc := &redisDocument{
		ID:              string(tx.ID),
		ExpireAt:        time.Now().UTC().Add(s.defaultTTL),
		TransactionData: &tx.TransactionData,
	}

	pipeline := s.redisClient.API().TxPipeline()
	// Set transactionIDBasedKey that points to intermediateKey
	pipeline.Set(ctx, transactionIDBasedKey, intermediateKey, s.defaultTTL)
	// Set opStatueBasedKey that points to intermediateKey
	pipeline.Set(ctx, opStatueBasedKey, intermediateKey, s.defaultTTL)
	// Set intermediateKey that points to redisDocument
	pipeline.Set(ctx, intermediateKey, doc, s.defaultTTL)

	if _, err = pipeline.Exec(ctx); err != nil {
		return fmt.Errorf("transactionData Update: %w", err)
	}

	return nil
}

func resolveRedisKey(prefix, id string) string {
	return fmt.Sprintf("%s-%s", prefix, id)
}
