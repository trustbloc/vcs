package privateapi

//go:generate mockgen -destination privateapi_mocks_test.go -package privateapi_test -source=privateapi.go -mock_names httpClient=MockHttpClient

import (
	"context"
	"fmt"
	"net/http"
)

const (
	prepareClaimDataAuthEndpoint = "/issuer/interactions/prepare-claim-data-authz-request"
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

func (c *Client) PrepareClaimDataAuthZ(
	ctx context.Context,
	req *PrepareClaimDataAuthZRequest,
) (*PrepareClaimDataAuthZResponse, error) {
	return sendInternal[PrepareClaimDataAuthZRequest, PrepareClaimDataAuthZResponse](
		ctx,
		c.client,
		http.MethodPost,
		fmt.Sprintf("%s%s", c.hostURI, prepareClaimDataAuthEndpoint),
		req,
	)
}
