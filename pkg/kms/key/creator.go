/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key //nolint: cyclop

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	jose2 "github.com/go-jose/go-jose/v3"
	"github.com/trustbloc/kms-go/crypto/primitive/bbs12381g2pub"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/doc/util/jwkkid"
	"github.com/trustbloc/kms-go/spi/kms"
)

type keyManager interface {
	CreateAndExportPubKeyBytes(kt kms.KeyType, opts ...kms.KeyOpts) (string, []byte, error)
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
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
		case kms.ECDSASecp256k1DER:
			var pki publicKeyInfo
			var rest []byte
			if rest, err = asn1.Unmarshal(keyBytes, &pki); err != nil {
				return "", nil, err
			} else if len(rest) != 0 {
				return "", nil, fmt.Errorf("x509: trailing data after ASN.1 of public-key")
			}

			var pubKey *btcec.PublicKey
			pubKey, err = btcec.ParsePubKey(pki.PublicKey.RightAlign(), btcec.S256())
			if err != nil {
				return "", nil, err
			}

			j, err = jwksupport.JWKFromKey(pubKey.ToECDSA())
			if err != nil {
				return "", nil, err
			}
		case kms.BLS12381G2Type:
			j, err = jwksupport.PubKeyBytesToJWK(keyBytes, kt)
			if err != nil {
				return "", nil, err
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
		case kms.ECDSASecp256k1DER:
			var pki publicKeyInfo
			var rest []byte
			if rest, err = asn1.Unmarshal(keyBytes, &pki); err != nil {
				return "", nil, err
			} else if len(rest) != 0 {
				return "", nil, fmt.Errorf("x509: trailing data after ASN.1 of public-key")
			}

			var btPK *btcec.PublicKey
			btPK, err = btcec.ParsePubKey(pki.PublicKey.RightAlign(), btcec.S256())
			if err != nil {
				return "", nil, err
			}

			pubKey = btPK.ToECDSA()
		case kms.BLS12381G2Type:
			pubKey, err = bbs12381g2pub.UnmarshalPublicKey(keyBytes)
			if err != nil {
				return "", nil, err
			}
		default:
			return "", nil, fmt.Errorf("unsupported key type: %s", kt)
		}

		return keyID, pubKey, nil
	}
}
