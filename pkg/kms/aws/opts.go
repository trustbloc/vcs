/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws

import (
	"os"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type opts struct {
	keyAliasPrefix      string
	awsClient           awsClient
	encryptionAlgorithm string
}

// NewOpts create new opts populated with environment variable.
func newOpts() *opts {
	value, _ := os.LookupEnv("AWS_KEY_ALIAS_PREFIX")

	return &opts{
		keyAliasPrefix:      value,
		encryptionAlgorithm: string(types.EncryptionAlgorithmSpecSymmetricDefault),
	}
}

func (o *opts) KeyAliasPrefix() string {
	return o.keyAliasPrefix
}

// Opts a Functional Options.
type Opts func(opts *opts)

// WithKeyAliasPrefix sets the given prefix in the returns Opts.
func WithKeyAliasPrefix(prefix string) Opts {
	return func(opts *opts) { opts.keyAliasPrefix = prefix }
}

// WithEncryptionAlgorithm sets the encryption\decryption algorithm Opts.
func WithEncryptionAlgorithm(algo string) Opts {
	return func(opts *opts) { opts.encryptionAlgorithm = algo }
}

// WithAWSClient sets custom AWS client.
func WithAWSClient(client awsClient) Opts {
	return func(opts *opts) { opts.awsClient = client }
}
