/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"fmt"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func (s *Service) validateStateTransition(
	oldState issuecredential.TransactionState,
	newState issuecredential.TransactionState,
) error {
	if oldState == issuecredential.TransactionStateIssuanceInitiated &&
		newState == issuecredential.TransactionStatePreAuthCodeValidated {
		return nil // pre-auth 1
	}

	if oldState == issuecredential.TransactionStateIssuanceInitiated &&
		newState == issuecredential.TransactionStateAwaitingIssuerOIDCAuthorization {
		return nil // auth 1
	}

	if oldState == issuecredential.TransactionStateAwaitingIssuerOIDCAuthorization &&
		newState == issuecredential.TransactionStateIssuerOIDCAuthorizationDone {
		return nil
	}

	if oldState == issuecredential.TransactionStatePreAuthCodeValidated &&
		newState == issuecredential.TransactionStateCredentialsIssued {
		return nil
	}

	if oldState == issuecredential.TransactionStateIssuerOIDCAuthorizationDone &&
		newState == issuecredential.TransactionStateCredentialsIssued {
		return nil
	}

	return resterr.NewCustomError(resterr.InvalidStateTransition,
		fmt.Errorf("unexpected transition from %v to %v", oldState, newState))
}
