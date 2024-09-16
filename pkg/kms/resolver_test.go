/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"

	kms2 "github.com/trustbloc/vcs/pkg/kms"
)

func TestResolver(t *testing.T) {
	ep := &kms2.EndpointResolver{
		Endpoint: "http://localhost",
	}

	resp, err := ep.ResolveEndpoint(context.TODO(), kms.EndpointParameters{})
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	assert.Equal(t, "localhost", resp.URI.Host)
}
