/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"fmt"
)

func (s *Service) GetIssuanceState(ctx context.Context, txID string) (TransactionState, error) {
	tx, err := s.store.Get(ctx, TxID(txID))
	if err != nil {
		return TransactionStateUnknown, fmt.Errorf("get tx: %w", err)
	}

	return tx.State, nil
}

func (s *Service) validateStateTransition(
	oldState TransactionState,
	newState TransactionState,
) error {
	if oldState == TransactionStateIssuanceInitiated &&
		newState == TransactionStatePreAuthCodeValidated {
		return nil // pre-auth 1
	}

	if oldState == TransactionStateIssuanceInitiated &&
		newState == TransactionStateAwaitingIssuerOIDCAuthorization {
		return nil // auth 1
	}

	if oldState == TransactionStateAwaitingIssuerOIDCAuthorization &&
		newState == TransactionStateIssuerOIDCAuthorizationDone {
		return nil
	}

	if oldState == TransactionStatePreAuthCodeValidated &&
		newState == TransactionStateCredentialsIssued {
		return nil
	}

	if oldState == TransactionStateIssuerOIDCAuthorizationDone &&
		newState == TransactionStateCredentialsIssued {
		return nil
	}

	return fmt.Errorf("unexpected transaction from %v to %v", oldState, newState)
}
