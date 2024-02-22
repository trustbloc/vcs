/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key //nolint: cyclop

import (
	"fmt"

	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
)

// JWKKeyCreator creates a new key of the given type using a given key manager, returning the key's ID
// and public key in JWK format.
func JWKKeyCreator(kc api.KeyCreator) func(kms.KeyType) (string, *jwk.JWK, error) {
	return func(kt kms.KeyType) (string, *jwk.JWK, error) {
		j, err := kc.Create(kt)
		if err != nil {
			return "", nil, fmt.Errorf("failed to convert key to JWK: %w", err)
		}

		return j.KeyID, j, nil
	}
}

// CryptoKeyCreator creates a new key of the given type using a given key manager, returning the key's ID
// and public key in one of the crypto.PublicKey formats.
func CryptoKeyCreator(kc api.RawKeyCreator) func(kms.KeyType) (string, interface{}, error) {
	return func(kt kms.KeyType) (string, interface{}, error) {
		switch kt { // nolint:exhaustive // default catch-all
		case
			kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER,
			kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363,
			kms.ECDSASecp256k1DER,
			kms.BLS12381G2Type,
			kms.ED25519Type,
			kms.RSAPS256, kms.RSARS256:
			keyID, pubKey, err := kc.CreateRaw(kt)
			if err != nil {
				return "", nil, fmt.Errorf("failed to create new crypto key: %w", err)
			}

			return keyID, pubKey, nil
		default:
			return "", nil, fmt.Errorf("unsupported key type: %s", kt)
		}
	}
}
