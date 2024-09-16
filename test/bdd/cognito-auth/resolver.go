/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	transport "github.com/aws/smithy-go/endpoints"
)

// EndpointResolver resolves the endpoint.
type EndpointResolver struct {
	Endpoint string
}

// ResolveEndpoint resolves the endpoint.
func (e *EndpointResolver) ResolveEndpoint(
	_ context.Context,
	_ kms.EndpointParameters,
) (transport.Endpoint, error) {
	targetURL, err := url.Parse(e.Endpoint)
	if err != nil {
		return transport.Endpoint{}, err
	}

	return transport.Endpoint{
		URI: *targetURL,
	}, nil
}
