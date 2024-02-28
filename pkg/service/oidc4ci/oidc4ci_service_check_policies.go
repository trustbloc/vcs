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

func (s *Service) CheckPolicies(
	ctx context.Context,
	profile *profile.Issuer,
	clientAssertionType,
	clientAssertion string,
	credentialTypes []string) error {
	if err := s.validateClientAssertionConfig(profile, clientAssertionType, clientAssertion); err != nil {
		return err
	}

	if profile.Checks.Policy.PolicyURL != "" {
		if err := s.trustRegistryService.ValidateIssuance(ctx, profile, clientAssertion, credentialTypes); err != nil {
			return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed, err)
		}
	}

	return nil
}

func (s *Service) validateClientAssertionConfig(
	profile *profile.Issuer,
	clientAssertionType,
	clientAssertion string) error {
	if profile.OIDCConfig == nil || !lo.Contains(profile.OIDCConfig.TokenEndpointAuthMethodsSupported,
		attestJWTClientAuthType) {
		return nil
	}

	if profile.Checks.Policy.PolicyURL == "" {
		// This is a profile configuration error
		return errors.New("client attestation is required but policy url not set for profile")
	}

	if clientAssertionType == "" {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("no client assertion type specified"))
	}

	if clientAssertionType != attestJWTClientAuthType {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("only supported client assertion type is attest_jwt_client_auth"))
	}

	if clientAssertion == "" {
		return resterr.NewCustomError(resterr.OIDCClientAuthenticationFailed,
			errors.New("client_assertion is required"))
	}

	return nil
}
