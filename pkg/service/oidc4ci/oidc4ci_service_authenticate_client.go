/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"errors"

	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

const attestJWTClientAuthType = "attest_jwt_client_auth"

func (s *Service) AuthenticateClient(
	ctx context.Context,
	profile *profile.Issuer,
	clientAssertionType,
	clientAssertion string) error {
	if profile.OIDCConfig == nil || !lo.Contains(profile.OIDCConfig.TokenEndpointAuthMethodsSupported,
		attestJWTClientAuthType) {
		return nil
	}

	if profile.Policy.URL == "" {
		return errors.New("policy url not set for profile") // this is profile configuration error
	}

	if clientAssertionType != "attest_jwt_client_auth" {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("only supported client assertion type is attest_jwt_client_auth"))
	}

	if clientAssertion == "" {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("client_assertion is required"))
	}

	if err := s.clientAttestationService.ValidateIssuance(ctx, profile, clientAssertion); err != nil {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed, err)
	}

	return nil
}
