/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

func (s *Service) ExchangeAuthorizationCode(ctx context.Context, opState string) (TxID, error) {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return "", fmt.Errorf("get transaction by opstate: %w", err)
	}

	resp, err := s.oAuth2ClientFactory.GetClient(oauth2.Config{
		ClientID:     tx.ClientID,
		ClientSecret: tx.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   tx.AuthorizationEndpoint,
			TokenURL:  tx.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		Scopes: tx.Scope,
	}).Exchange(ctx, tx.IssuerAuthCode)

	if err != nil {
		return "", err
	}

	tx.IssuerToken = resp.AccessToken

	if err = s.store.Update(ctx, tx); err != nil {
		return "", err
	}

	return tx.ID, nil
}
