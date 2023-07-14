/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"fmt"

	"github.com/trustbloc/vcs/pkg/event/spi"
)

// StoreAuthorizationCode stores authorization code from issuer provider.
func (s *Service) StoreAuthorizationCode(
	ctx context.Context,
	opState string,
	code string,
) (TxID, error) {
	tx, err := s.store.FindByOpState(ctx, opState)

	if err != nil {
		return "", fmt.Errorf("get transaction by opstate: %w", err)
	}

	tx.IssuerAuthCode = code
	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return "", err
	}

	if err = s.sendTransactionEvent(ctx, tx, spi.IssuerOIDCInteractionAuthorizationCodeStored); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return "", err
	}

	return tx.ID, nil
}
