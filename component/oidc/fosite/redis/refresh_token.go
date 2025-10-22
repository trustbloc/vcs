/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"errors"

	"github.com/ory/fosite"
	"github.com/redis/go-redis/v9"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
)

func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	return s.createSession(ctx, dto.RefreshTokenSegment, signature, request, defaultTTL)
}

func (s *Store) GetRefreshTokenSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	return s.getSession(ctx, dto.RefreshTokenSegment, signature, session)
}

func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	lookupIDBasedKey := resolveRedisKey(dto.RefreshTokenSegment, signature)

	intermediateKey, err := s.redisClient.API().Get(ctx, lookupIDBasedKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// If intermediateKey is not accessible - consider that the session is already deleted.
			return nil
		}

		return err
	}

	return s.redisClient.API().Del(ctx, intermediateKey, lookupIDBasedKey).Err()
}

func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	requestIDBasedKey := resolveRedisKey(dto.RefreshTokenSegment, requestID)

	intermediateKey, err := s.redisClient.API().Get(ctx, requestIDBasedKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// If intermediateKey is not accessible - consider that the session is already deleted.
			return nil
		}

		return err
	}

	return s.redisClient.API().Del(ctx, intermediateKey, requestIDBasedKey).Err()
}

func (s *Store) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	if err := s.RevokeRefreshToken(ctx, requestID); err != nil {
		return err
	}

	return s.DeleteRefreshTokenSession(ctx, signature)
}

func (s *Store) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	// Revoke the refresh token by requestID
	if err := s.RevokeRefreshToken(ctx, requestID); err != nil {
		return err
	}
	if err := s.DeleteRefreshTokenSession(ctx, refreshTokenSignature); err != nil {
		return err
	}
	return nil
}
