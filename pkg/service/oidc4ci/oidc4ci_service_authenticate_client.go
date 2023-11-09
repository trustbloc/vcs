/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"errors"
	"strings"

	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

const (
	attestJWTClientAuthType     = "attest_jwt_client_auth"
	attestJWTClientAuthJWTCount = 2
)

func (s *Service) AuthenticateClient(
	ctx context.Context,
	profile *profile.Issuer,
	clientID,
	clientAssertionType,
	clientAssertion string) error {
	if profile.OIDCConfig == nil || !lo.Contains(profile.OIDCConfig.TokenEndpointAuthMethodsSupported,
		attestJWTClientAuthType) {
		return nil
	}

	if clientID == "" {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("client_id is required"))
	}

	if clientAssertionType != "attest_jwt_client_auth" {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("only supported client assertion type is attest_jwt_client_auth"))
	}

	jwts := strings.Split(clientAssertion, "~")

	if len(jwts) != attestJWTClientAuthJWTCount {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("invalid client assertion format"))
	}

	if err := s.attestationService.ValidateClientAttestationJWT(ctx, clientID, jwts[0]); err != nil {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed, err)
	}

	if err := s.attestationService.ValidateClientAttestationPoPJWT(ctx, clientID, jwts[1]); err != nil {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed, err)
	}

	return nil
}
