/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws //nolint:testpackage

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	transport "github.com/aws/smithy-go/endpoints"
	"github.com/stretchr/testify/require"
)

func TestOpts(t *testing.T) {
	t.Run("options: defaults", func(t *testing.T) {
		options := newOpts()

		require.Equal(t, "", options.KeyAliasPrefix())
	})

	t.Run("options: set manually", func(t *testing.T) {
		options := newOpts()

		WithKeyAliasPrefix("keyaliasprefix")(options)

		require.Equal(t, "keyaliasprefix", options.KeyAliasPrefix())
	})

	t.Run("options: env vars", func(t *testing.T) {
		t.Setenv("AWS_KEY_ALIAS_PREFIX", "keyaliasprefix")

		options := newOpts()

		require.Equal(t, "keyaliasprefix", options.KeyAliasPrefix())
	})

	t.Run("options: endpoint resolver", func(t *testing.T) {
		options := newOpts()

		WithAWSEndpointResolverV2(&ExampleResolver{})(options)

		require.NotNil(t, options.endpointResolver)
	})
}

// ExampleResolver is an example resolver.
type ExampleResolver struct{}

// ResolveEndpoint resolves the endpoint.
func (e *ExampleResolver) ResolveEndpoint(_ context.Context, _ kms.EndpointParameters) (transport.Endpoint, error) {
	panic("do not call and it will be fine")
}
