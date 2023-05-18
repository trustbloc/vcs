/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oauth2util

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func Token(ctx context.Context, oidcProviderURL, clientID, secret string, scopes []string, tls *tls.Config) (string, error) {
	conf := clientcredentials.Config{
		TokenURL:     oidcProviderURL + "/oauth2/token",
		ClientID:     clientID,
		ClientSecret: secret,
		Scopes:       scopes,
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tls,
		},
	})

	token, err := conf.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	return token.AccessToken, nil
}
