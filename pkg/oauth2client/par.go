/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oauth2client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/context/ctxhttp"
	"golang.org/x/oauth2"
)

type parResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (c *Client) AuthCodeURLWithPAR(
	ctx context.Context,
	cfg oauth2.Config,
	parEndpoint string,
	state string,
	client *http.Client,
	opts ...AuthCodeOption,
) (string, error) {
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {cfg.ClientID},
		"state":         {state},
	}
	if cfg.RedirectURL != "" {
		v.Set("redirect_uri", cfg.RedirectURL)
	}
	if len(cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(cfg.Scopes, " "))
	}

	for _, opt := range opts {
		opt.setValue(v)
	}

	resp, err := ctxhttp.PostForm(ctx, client, parEndpoint, v)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected status code %v", resp.StatusCode)
	}

	var response parResponse
	if err = json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}
	_ = resp.Body.Close()

	return fmt.Sprintf("%v?%v", cfg.Endpoint.AuthURL, url.Values{
		"client_id":   {cfg.ClientID},
		"request_uri": {response.RequestURI},
	}.Encode()), nil
}
