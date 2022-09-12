/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination mocks/kms_mocks.go -self_package mocks -package mocks -source=kms.go -mock_names VCSKeyManager=MockVCSKeyManager

package kms

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/vcs/pkg/doc/vc"
)

type Type string

const (
	AWS   Type = "aws"
	Local Type = "local"
	Web   Type = "web"
)

// Config configure kms that stores signing keys.
type Config struct {
	KMSType  Type
	Endpoint string

	SecretLockKeyPath string
	DBType            string
	DBURL             string
	DBPrefix          string
}

type VCSKeyManager interface {
	SupportedKeyTypes() []kms.KeyType
	CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error)
	CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error)
	NewVCSigner(creator string, signatureType vc.SignatureType) (vc.SignerAlgorithm, error)
}
