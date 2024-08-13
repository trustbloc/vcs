/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func TestValidateTransition(t *testing.T) {
	s, err := NewService(&Config{})
	assert.NoError(t, err)

	testCases := []struct {
		from issuecredential.TransactionState
		to   issuecredential.TransactionState
	}{
		{
			from: issuecredential.TransactionStateIssuanceInitiated,
			to:   issuecredential.TransactionStatePreAuthCodeValidated,
		},
		{
			from: issuecredential.TransactionStateIssuanceInitiated,
			to:   issuecredential.TransactionStateAwaitingIssuerOIDCAuthorization,
		},
		{
			from: issuecredential.TransactionStateAwaitingIssuerOIDCAuthorization,
			to:   issuecredential.TransactionStateIssuerOIDCAuthorizationDone,
		},
		{
			from: issuecredential.TransactionStatePreAuthCodeValidated,
			to:   issuecredential.TransactionStateCredentialsIssued,
		},
		{
			from: issuecredential.TransactionStateIssuerOIDCAuthorizationDone,
			to:   issuecredential.TransactionStateCredentialsIssued,
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

	assert.ErrorContains(t, s.validateStateTransition(
		issuecredential.TransactionStateUnknown,
		issuecredential.TransactionStateIssuanceInitiated,
	), "unexpected transition from 0 to 1")
}
