/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapiclient

//go:generate mockgen -destination restapiclient_mocks_test.go -package restapiclient_test -source=restapiclient.go -mock_names httpClient=MockHttpClient

import (
	"context"
	"fmt"
	"net/http"
)

const (
	prepareClaimDataAuthEndpoint   = "/issuer/interactions/prepare-claim-data-authz-request"
	storeAuthorizationCodeEndpoint = "/issuer/interactions/store-authorization-code"
	pushAuthorizationEndpoint      = "/issuer/interactions/push-authorization"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	hostURI string
	client  httpClient
}

func NewClient(
	hostURI string,
	client httpClient,
) *Client {
	return &Client{
		hostURI: hostURI,
		client:  client,
	}
}

func (c *Client) PrepareClaimDataAuthorization(
	ctx context.Context,
	req *PrepareClaimDataAuthorizationRequest,
) (*PrepareClaimDataAuthorizationResponse, error) {
	return sendInternal[PrepareClaimDataAuthorizationRequest, PrepareClaimDataAuthorizationResponse](
		ctx,
		c.client,
		http.MethodPost,
		fmt.Sprintf("%s%s", c.hostURI, prepareClaimDataAuthEndpoint),
		req,
	)
}

func (c *Client) StoreAuthorizationCode(
	ctx context.Context,
	req *StoreAuthorizationCodeRequest,
) (*StoreAuthorizationCodeResponse, error) {
	return sendInternal[StoreAuthorizationCodeRequest, StoreAuthorizationCodeResponse](
		ctx,
		c.client,
		http.MethodPost,
		fmt.Sprintf("%s%s", c.hostURI, storeAuthorizationCodeEndpoint),
		req,
	)
}

func (c *Client) PushAuthorizationRequest(
	ctx context.Context,
	req *PushAuthorizationRequest,
) (*PushAuthorizationResponse, error) {
	return sendInternal[PushAuthorizationRequest, PushAuthorizationResponse](
		ctx,
		c.client,
		http.MethodPost,
		fmt.Sprintf("%s%s", c.hostURI, pushAuthorizationEndpoint),
		req,
	)
}
