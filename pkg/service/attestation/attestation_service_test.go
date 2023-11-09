/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package attestation_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/service/attestation"
)

func TestService_ValidateClientAttestationJWT(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))

	var clientID, clientAttestationJWT string

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name:  "success",
			setup: func() {},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc := attestation.NewService(&attestation.Config{
				HTTPClient: httpClient,
			})

			err := svc.ValidateClientAttestationJWT(context.Background(), clientID, clientAttestationJWT)
			tt.check(t, err)
		})
	}
}

func TestService_ValidateClientAttestationPoPJWT(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))

	var clientID, clientAttestationPoPJWT string

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name:  "success",
			setup: func() {},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc := attestation.NewService(&attestation.Config{
				HTTPClient: httpClient,
			})

			err := svc.ValidateClientAttestationPoPJWT(context.Background(), clientID, clientAttestationPoPJWT)
			tt.check(t, err)
		})
	}
}
