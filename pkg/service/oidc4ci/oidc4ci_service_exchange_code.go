/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc6749"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func (s *Service) ExchangeAuthorizationCode(
	ctx context.Context,
	opState,
	clientID, // nolint:revive
	clientAssertionType,
	clientAssertion string,
) (*ExchangeAuthorizationCodeResult, error) {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return nil, rfc6749.NewInvalidGrantError(fmt.Errorf("get transaction by opstate: %w", err))
	}

	newState := issuecredential.TransactionStateIssuerOIDCAuthorizationDone
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		e := rfc6749.NewInvalidRequestError(err).WithErrorPrefix("validateStateTransition")

		s.sendFailedTransactionEvent(ctx, tx, e.Error(), e.Code(), e.ErrorComponent)

		return nil, e
	}

	tx.State = newState

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		e := rfc6749.NewInvalidRequestError(err).WithErrorPrefix("getProfile")

		s.sendFailedTransactionEvent(ctx, tx, e.Error(), e.Code(), e.ErrorComponent)

		return nil, e
	}

	if err = s.checkPolicy(ctx, profile, tx, clientAssertionType, clientAssertion); err != nil {
		e := rfc6749.NewInvalidRequestError(err).WithErrorPrefix("check policy")

		s.sendFailedTransactionEvent(ctx, tx, e.Error(), e.Code(), e.ErrorComponent)

		return nil, e
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
		e := rfc6749.NewInvalidGrantError(err).WithErrorPrefix("oauth2Client.Exchange")

		s.sendFailedTransactionEvent(ctx, tx, e.Error(), e.Code(), e.ErrorComponent)

		return nil, e
	}

	tx.IssuerToken = resp.AccessToken

	if err = s.store.Update(ctx, tx); err != nil {
		e := rfc6749.NewInvalidRequestError(err).WithErrorPrefix("update store")

		s.sendFailedTransactionEvent(ctx, tx, e.Error(), e.Code(), e.ErrorComponent)

		return nil, e
	}

	if err = s.sendTransactionEvent(
		ctx,
		tx,
		spi.IssuerOIDCInteractionAuthorizationCodeExchanged,
		nil,
	); err != nil {
		return nil, rfc6749.NewInvalidRequestError(err).WithErrorPrefix("update store")
	}

	exchangeAuthorizationCodeResult := &ExchangeAuthorizationCodeResult{
		TxID: tx.ID,
	}

	for _, credentialConfiguration := range tx.CredentialConfiguration {
		// AuthorizationDetails REQUIRED when authorization_details parameter is used to request issuance
		// of a certain Credential type in Authorization Request. It MUST NOT be used otherwise.
		if credentialConfiguration.AuthorizationDetails != nil {
			exchangeAuthorizationCodeResult.AuthorizationDetails = append(
				exchangeAuthorizationCodeResult.AuthorizationDetails,
				credentialConfiguration.AuthorizationDetails,
			)
		}
	}

	return exchangeAuthorizationCodeResult, nil
}
