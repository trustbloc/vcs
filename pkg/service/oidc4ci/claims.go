/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"

	"github.com/trustbloc/vcs/internal/claims"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func (s *Service) EncryptClaims(ctx context.Context, data map[string]interface{}) (*issuecredential.ClaimData, error) {
	return claims.EncryptClaims(ctx, data, s.dataProtector)
}

func (s *Service) DecryptClaims(ctx context.Context, data *issuecredential.ClaimData) (map[string]interface{}, error) {
	return claims.DecryptClaims(ctx, data, s.dataProtector)
}
