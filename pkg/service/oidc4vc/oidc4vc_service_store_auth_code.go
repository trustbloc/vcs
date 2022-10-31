/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"context"
	"fmt"
)

// StoreAuthCode stores authorization code from issuer provider.
func (s *Service) StoreAuthCode(
	ctx context.Context,
	opState string,
	code string,
) (TxID, error) {
	tx, err := s.store.FindByOpState(ctx, opState)

	if err != nil {
		return "", fmt.Errorf("get transaction by opstate: %w", err)
	}

	tx.IssuerAuthCode = code

	return tx.ID, s.store.Update(ctx, tx)
}
