/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"fmt"
	"strings"

	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

// StoreAuthorizationCode stores authorization code from issuer provider.
func (s *Service) StoreAuthorizationCode(
	ctx context.Context,
	opState string,
	code string,
	flowData *common.WalletInitiatedFlowData,
) (issuecredential.TxID, error) {
	var tx *issuecredential.Transaction
	var err error
	if flowData != nil { // it's wallet initiated issuance, first we need to initiate issuance
		tx, err = s.initiateIssuanceWithWalletFlow(ctx, flowData)
	} else {
		tx, err = s.store.FindByOpState(ctx, opState)
	}

	if err != nil {
		return "", err
	}

	tx.IssuerAuthCode = code
	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedTransactionEvent(
			ctx, tx, err.Error(), resterr.SystemError, resterr.TransactionStoreComponent)

		return "", err
	}

	if err = s.sendTransactionEvent(
		ctx,
		tx,
		spi.IssuerOIDCInteractionAuthorizationCodeStored,
		nil,
	); err != nil {
		return "", err
	}

	return tx.ID, nil
}

func (s *Service) initiateIssuanceWithWalletFlow(
	ctx context.Context,
	flowData *common.WalletInitiatedFlowData,
) (*issuecredential.Transaction, error) {
	profile, err := s.profileService.GetProfile(flowData.ProfileId, flowData.ProfileVersion)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, resterr.ErrProfileNotFound
		}

		return nil, fmt.Errorf("get profile: %w", err)
	}

	profile.Version = flowData.ProfileVersion // wallet flow aud check should match

	tx, err := s.InitiateIssuance(ctx, &InitiateIssuanceRequest{
		ClientInitiateIssuanceURL: "",
		ClientWellKnownURL:        "",
		GrantType:                 "authorization_code",
		ResponseType:              "code",
		Scope:                     lo.FromPtr(flowData.Scopes),
		OpState:                   flowData.OpState,
		UserPinRequired:           false,
		WalletInitiatedIssuance:   true,
		CredentialConfiguration: []InitiateIssuanceCredentialConfiguration{
			{
				ClaimData:             nil,
				ComposeCredential:     nil,
				ClaimEndpoint:         flowData.ClaimEndpoint,
				CredentialTemplateID:  flowData.CredentialTemplateId,
				CredentialExpiresAt:   nil,
				CredentialName:        "",
				CredentialDescription: "",
			},
		},
	}, profile)
	if err != nil {
		return nil, fmt.Errorf("can not initiate issuance for wallet-initiated flow: %w", err)
	}

	return tx.Tx, nil
}
