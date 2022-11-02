/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oauth_client_mocks_test.go -self_package mocks -package oidc4vc_test -source=oauth_client.go -mock_names OAuth2Client=MockOAuth2Client

package oidc4vc

import (
	"context"

	"golang.org/x/oauth2"
)

type OAuth2ClientFactory struct {
}

type OAuth2Client interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
}

func NewOAuth2ClientFactory() *OAuth2ClientFactory {
	return &OAuth2ClientFactory{}
}

func (o *OAuth2ClientFactory) GetClient(config oauth2.Config) OAuth2Client {
	return &config
}
