/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination mocks/kms_mocks.go -self_package mocks -package mocks -source=kms.go -mock_names VCSKeyManager=MockVCSKeyManager

package kms

import (
	"net/http"

	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

type Type string

const (
	AWS   Type = "aws"
	Local Type = "local"
	Web   Type = "web"
)

// Config configure kms that stores signing keys.
type Config struct {
	KMSType     Type `json:"kmsType"`
	Endpoint    string
	Region      string
	AliasPrefix string
	HTTPClient  *http.Client

	SecretLockKeyPath string
	DBType            string
	DBURL             string
	DBPrefix          string
	MasterKey         string
}

type VCSKeyManager interface {
	SupportedKeyTypes() []kms.KeyType
	CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error)
	CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error)
	NewVCSigner(creator string, signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error)
}
