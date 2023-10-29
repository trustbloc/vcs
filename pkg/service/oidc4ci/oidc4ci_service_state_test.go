/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTransition(t *testing.T) {
	s, err := NewService(&Config{})
	assert.NoError(t, err)

	testCases := []struct {
		from TransactionState
		to   TransactionState
	}{
		{
			from: TransactionStateIssuanceInitiated,
			to:   TransactionStatePreAuthCodeValidated,
		},
		{
			from: TransactionStateIssuanceInitiated,
			to:   TransactionStateAwaitingIssuerOIDCAuthorization,
		},
		{
			from: TransactionStateAwaitingIssuerOIDCAuthorization,
			to:   TransactionStateIssuerOIDCAuthorizationDone,
		},
		{
			from: TransactionStatePreAuthCodeValidated,
			to:   TransactionStateCredentialsIssued,
		},
		{
			from: TransactionStateIssuerOIDCAuthorizationDone,
			to:   TransactionStateCredentialsIssued,
		},
	}

	for _, tCase := range testCases {
		t.Run(fmt.Sprintf("from %v to %v", tCase.from, tCase.to), func(t *testing.T) {
			assert.NoError(t, s.validateStateTransition(tCase.from, tCase.to))
		})
	}
}

func TestInvalidTransition(t *testing.T) {
	s, err := NewService(&Config{})
	assert.NoError(t, err)

	assert.ErrorContains(t, s.validateStateTransition(TransactionStateUnknown, TransactionStateIssuanceInitiated),
		"unexpected transition from 0 to 1")
}
