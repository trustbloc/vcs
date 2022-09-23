/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	jose2 "github.com/square/go-jose/v3"
)

type keyManager interface {
	CreateAndExportPubKeyBytes(kt kms.KeyType, opts ...kms.KeyOpts) (string, []byte, error)
}

// JWKKeyCreator creates a new key of the given type using a given key manager, returning the key's ID
// and public key in JWK format.
func JWKKeyCreator(kt kms.KeyType) func(keyManager) (string, *jwk.JWK, error) {
	return func(km keyManager) (string, *jwk.JWK, error) {
		keyID, keyBytes, err := km.CreateAndExportPubKeyBytes(kt)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create new JWK key: %w", err)
		}

		var j *jwk.JWK

		switch kt { // nolint:exhaustive // deferring all other key types to BuildJWK().
		case kms.ED25519Type:
			j = &jwk.JWK{
				JSONWebKey: jose2.JSONWebKey{
					Key:   ed25519.PublicKey(keyBytes),
					KeyID: keyID,
				},
				Kty: "OKP",
				Crv: "Ed25519", // TODO where is the constant for this?
			}
		default:
			var err error

			j, err = jwkkid.BuildJWK(keyBytes, kt)
			if err != nil {
				return "", nil, fmt.Errorf("failed to convert key to JWK: %w", err)
			}
		}

		return keyID, j, nil
	}
}

// CryptoKeyCreator creates a new key of the given type using a given key manager, returning the key's ID
// and public key in one of the crypto.PublicKey formats.
func CryptoKeyCreator(kt kms.KeyType) func(keyManager) (string, interface{}, error) {
	return func(km keyManager) (string, interface{}, error) {
		keyID, keyBytes, err := km.CreateAndExportPubKeyBytes(kt)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create new crypto key: %w", err)
		}

		var pubKey interface{}

		switch kt { // nolint:exhaustive // default catch-all
		case kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER:
			pubKey, err = x509.ParsePKIXPublicKey(keyBytes)
			if err != nil {
				return "", nil, fmt.Errorf("failed to parse ecdsa key in DER format: %w", err)
			}
		case kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363:
			curves := map[kms.KeyType]elliptic.Curve{
				kms.ECDSAP256TypeIEEEP1363: elliptic.P256(),
				kms.ECDSAP384TypeIEEEP1363: elliptic.P384(),
				kms.ECDSAP521TypeIEEEP1363: elliptic.P521(),
			}
			crv := curves[kt]
			x, y := elliptic.Unmarshal(crv, keyBytes)
			pubKey = &ecdsa.PublicKey{
				Curve: crv,
				X:     x,
				Y:     y,
			}
		case kms.ED25519Type:
			pubKey = ed25519.PublicKey(keyBytes)
		default:
			return "", nil, fmt.Errorf("unsupported key type: %s", kt)
		}

		return keyID, pubKey, nil
	}
}
