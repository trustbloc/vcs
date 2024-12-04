/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package arieskmsstore

//go:generate mockgen -destination interfaces_mocks_test.go -package arieskmsstore_test -source=interfaces.go

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type Client interface {
	CreateSecret(
		ctx context.Context,
		params *secretsmanager.CreateSecretInput,
		optFns ...func(*secretsmanager.Options),
	) (*secretsmanager.CreateSecretOutput, error)

	GetSecretValue(
		ctx context.Context,
		params *secretsmanager.GetSecretValueInput,
		optFns ...func(*secretsmanager.Options),
	) (*secretsmanager.GetSecretValueOutput, error)

	DeleteSecret(
		ctx context.Context,
		params *secretsmanager.DeleteSecretInput,
		optFns ...func(*secretsmanager.Options),
	) (*secretsmanager.DeleteSecretOutput, error)
}
