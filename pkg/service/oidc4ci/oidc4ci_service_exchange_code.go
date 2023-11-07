/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

func (s *Service) ExchangeAuthorizationCode(
	ctx context.Context,
	opState,
	clientID,
	clientAssertionType,
	clientAssertion string,
) (TxID, error) {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return "", fmt.Errorf("get transaction by opstate: %w", err)
	}

	newState := TransactionStateIssuerOIDCAuthorizationDone
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return "", err
	}
	tx.State = newState

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		var e error

		if strings.Contains(err.Error(), "not found") {
			e = resterr.NewCustomError(resterr.ProfileNotFound, err)
		} else {
			e = resterr.NewSystemError(resterr.IssuerProfileSvcComponent, "GetProfile", err)
		}

		s.sendFailedTransactionEvent(ctx, tx, e)

		return "", e
	}

	if err = s.AuthenticateClient(ctx, profile, clientID, clientAssertionType, clientAssertion); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return "", resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed, err)
	}

	oauth2Client := oauth2.Config{
		ClientID:     profile.OIDCConfig.ClientID,
		ClientSecret: profile.OIDCConfig.ClientSecretHandle,
		Endpoint: oauth2.Endpoint{
			AuthURL:   tx.AuthorizationEndpoint,
			TokenURL:  tx.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: tx.RedirectURI,
		Scopes:      tx.Scope,
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)

	resp, err := oauth2Client.Exchange(ctx, tx.IssuerAuthCode)
	if err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return "", err
	}

	tx.IssuerToken = resp.AccessToken

	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedTransactionEvent(ctx, tx, err)
		return "", err
	}

	if err = s.sendTransactionEvent(ctx, tx, spi.IssuerOIDCInteractionAuthorizationCodeExchanged); err != nil {
		return "", err
	}

	return tx.ID, nil
}
