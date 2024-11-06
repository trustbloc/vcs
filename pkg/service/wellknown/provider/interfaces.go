/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"context"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

//go:generate mockgen -destination interfaces_mocks_test.go -package provider -source=interfaces.go

type dynamicWellKnownStore interface {
	Upsert(
		ctx context.Context,
		profileID string,
		item map[string]*profileapi.CredentialsConfigurationSupported,
	) error
	Get(ctx context.Context, profileID string) (map[string]*profileapi.CredentialsConfigurationSupported, error)
}
