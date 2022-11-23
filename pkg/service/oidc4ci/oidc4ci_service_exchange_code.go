/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/event/spi"
)

func (s *Service) ExchangeAuthorizationCode(ctx context.Context, opState string) (TxID, error) {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return "", fmt.Errorf("get transaction by opstate: %w", err)
	}

	newState := TransactionStateIssuerOIDCAuthorizationDone
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		s.sendFailedEvent(tx, err)
		return "", err
	}
	tx.State = newState

	resp, err := s.oAuth2Client.Exchange(ctx, oauth2.Config{
		ClientID:     tx.ClientID,
		ClientSecret: tx.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   tx.AuthorizationEndpoint,
			TokenURL:  tx.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: tx.RedirectURI,
		Scopes:      tx.Scope,
	}, tx.IssuerAuthCode, s.httpClient.(*http.Client)) // TODO: Fix this!
	if err != nil {
		s.sendFailedEvent(tx, err)
		return "", err
	}

	tx.IssuerToken = resp.AccessToken

	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedEvent(tx, err)
		return "", err
	}

	if err = s.sendEvent(tx, spi.IssuerOIDCInteractionAuthorizationCodeExchanged); err != nil {
		return "", err
	}

	return tx.ID, nil
}
