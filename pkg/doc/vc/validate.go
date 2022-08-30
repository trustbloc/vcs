/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	jwtVC = "jwt_vc"
	ldpVC = "ldp_vc"
)

/*
"*/

func ValidateVCFormat(format string) error {
	if format != jwtVC && format != ldpVC {
		return fmt.Errorf("unsupported vc format %s, use one of next [%s, %s]", format, jwtVC, ldpVC)
	}
	return nil
}

// SignatureType type of signature used to sign vc.
type SignatureType string

const (
	EdDSA  SignatureType = "EdDSA"
	ES256K SignatureType = "ES256K"
	ES256  SignatureType = "ES256"
	ES384  SignatureType = "ES384"
	PS256  SignatureType = "PS256"

	Ed25519Signature2018        SignatureType = "Ed25519Signature2018"
	Ed25519Signature2020        SignatureType = "Ed25519Signature2020"
	EcdsaSecp256k1Signature2019 SignatureType = "EcdsaSecp256k1Signature2019"
	BbsBlsSignature2020         SignatureType = "BbsBlsSignature2020"
	JSONWebSignature2020        SignatureType = "JsonWebSignature2020"
)

// Name of signature type.
func (st SignatureType) Name() string {
	return string(st)
}

// lowerCase name of signature type in lower case. Used internally.
func (st SignatureType) lowerCase() string {
	return strings.ToLower(string(st))
}

func ValidateVCSignatureAlgorithm(format, signatureType string) (SignatureType, error) {
	var validSignatureTypes []SignatureType

	if format == jwtVC {
		validSignatureTypes = []SignatureType{
			EdDSA,
			ES256K,
			ES256,
			ES384,
			PS256,
		}
	}

	if format == ldpVC {
		validSignatureTypes = []SignatureType{
			Ed25519Signature2018,
			Ed25519Signature2020,
			EcdsaSecp256k1Signature2019,
			BbsBlsSignature2020,
			JSONWebSignature2020,
		}
	}

	if validSignatureTypes == nil {
		return "", fmt.Errorf("unsupported vc format %s", format)
	}

	for _, val := range validSignatureTypes {
		if val.lowerCase() == strings.ToLower(signatureType) {
			return val, nil
		}
	}

	return "", fmt.Errorf("unsupported siganture type %s by vc format %s", signatureType, format)
}

func matchKeyType(keyType string, types ...kms.KeyType) (kms.KeyType, error) {
	if keyType == "" && len(types) == 1 {
		return types[0], nil
	}

	var keyTypesNames []string

	for _, possibleType := range types {
		keyTypesNames = append(keyTypesNames, string(possibleType))

		if keyType == string(possibleType) {
			return possibleType, nil
		}
	}

	if keyType == "" && len(types) > 1 {
		return "", fmt.Errorf("key type should have one of the values %s", strings.Join(keyTypesNames, ","))
	}

	return "", fmt.Errorf("not supported key type %s, should have one of the values %s", keyType,
		strings.Join(keyTypesNames, ","))
}

func ValidateSignatureKeyType(signatureType SignatureType, keyType string) (kms.KeyType, error) {
	switch signatureType.lowerCase() {
	case Ed25519Signature2018.lowerCase(), Ed25519Signature2020.lowerCase(), EdDSA.lowerCase():
		return matchKeyType(keyType, kms.ED25519Type)
	case EcdsaSecp256k1Signature2019.lowerCase(), ES256K.lowerCase():
		return matchKeyType(keyType, kms.ECDSASecp256k1TypeIEEEP1363)
	case BbsBlsSignature2020.lowerCase():
		return matchKeyType(keyType, kms.BLS12381G2Type)
	case JSONWebSignature2020.lowerCase():
		return matchKeyType(keyType, kms.ED25519Type, kms.X25519ECDHKWType,
			kms.ECDSASecp256k1TypeIEEEP1363, kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.RSAPS256Type)
	case ES256.lowerCase():
		return matchKeyType(keyType, kms.ECDSAP256TypeDER)
	case ES384.lowerCase():
		return matchKeyType(keyType, kms.ECDSAP384TypeDER)
	case PS256.lowerCase():
		return matchKeyType(keyType, kms.RSAPS256Type)
	}

	return "", fmt.Errorf("%s signature type currently not supported", signatureType)
}
