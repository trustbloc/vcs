/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
	"github.com/trustbloc/vcs/pkg/oauth2client"
)

// InsertClient is not required by original interfaces, can be used for testing or data seeding.
func (s *Store) InsertClient(ctx context.Context, client oauth2client.Client) (string, error) {
	key := resolveRedisKey(dto.ClientsSegment, client.ID)

	obj := &genericDocument[oauth2client.Client]{
		Record: client,
	}

	return key, s.redisClient.API().Set(ctx, key, obj, defaultTTL).Err()
}
