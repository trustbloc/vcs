/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oauth_client_mocks_test.go -self_package mocks -package oauth2client_test -source=oauth_client.go -mock_names OAuth2Client=MockOAuth2Client

package oauth2client

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

type Client struct {
}

func NewOAuth2Client() *Client {
	return &Client{}
}

func (c *Client) Exchange(
	ctx context.Context,
	cfg oauth2.Config,
	code string,
	client *http.Client,
	opts ...oauth2.AuthCodeOption,
) (*oauth2.Token, error) {
	return (&cfg).Exchange(
		context.WithValue(ctx, oauth2.HTTPClient, client),
		code,
		opts...,
	)
}

func (c *Client) AuthCodeURL(_ context.Context, cfg oauth2.Config, state string, opts ...oauth2.AuthCodeOption) string {
	return (&cfg).AuthCodeURL(state, opts...)
}
