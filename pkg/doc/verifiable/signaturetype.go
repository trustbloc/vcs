/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

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

type signatureTypeDesc struct {
	SignatureType     SignatureType
	VCFormat          Format
	SupportedKeyTypes []kms.KeyType
}

// nolint: gochecknoglobals
var signatureTypes = []signatureTypeDesc{
	{Ed25519Signature2018, Ldp, []kms.KeyType{kms.ED25519Type}},
	{Ed25519Signature2020, Ldp, []kms.KeyType{kms.ED25519Type}},
	{EcdsaSecp256k1Signature2019, Ldp,
		[]kms.KeyType{kms.ECDSASecp256k1TypeIEEEP1363, kms.ECDSASecp256k1DER}},
	{BbsBlsSignature2020, Ldp, []kms.KeyType{kms.BLS12381G2Type}},
	{JSONWebSignature2020, Ldp, []kms.KeyType{
		kms.ED25519Type, kms.X25519ECDHKWType, kms.ECDSASecp256k1DER,
		kms.ECDSASecp256k1TypeIEEEP1363, kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.RSAPS256Type,
	}},
	{EdDSA, Jwt, []kms.KeyType{kms.ED25519Type}},
	{ES256K, Jwt, []kms.KeyType{kms.ECDSASecp256k1TypeIEEEP1363,
		kms.ECDSASecp256k1DER}},
	{ES256, Jwt, []kms.KeyType{kms.ECDSAP256TypeDER}},
	{ES384, Jwt, []kms.KeyType{kms.ECDSAP384TypeDER}},
	{PS256, Jwt, []kms.KeyType{kms.RSAPS256Type}},
}

func ValidateSignatureAlgorithm(format Format, signatureType string, kmsKeyTypes []kms.KeyType) (SignatureType, error) {
	for _, supportedSignature := range signatureTypes {
		if supportedSignature.SignatureType.lowerCase() == strings.ToLower(signatureType) &&
			supportedSignature.VCFormat == format && matchKeyTypes(kmsKeyTypes, supportedSignature.SupportedKeyTypes) {
			return supportedSignature.SignatureType, nil
		}
	}

	return "", fmt.Errorf("unsupported siganture type %s by vc format %s", signatureType, format)
}

func GetSignatureTypeByName(signatureType string) (SignatureType, error) {
	for _, supportedSignature := range signatureTypes {
		if supportedSignature.SignatureType.lowerCase() == strings.ToLower(signatureType) {
			return supportedSignature.SignatureType, nil
		}
	}

	return "", fmt.Errorf("unsupported siganture type %q", signatureType)
}

func GetJWTSignatureTypeByKey(keyType kms.KeyType) (SignatureType, error) {
	for _, supportedSignature := range signatureTypes {
		for _, supportedKeyType := range supportedSignature.SupportedKeyTypes {
			if supportedKeyType == keyType && supportedSignature.VCFormat == Jwt {
				return supportedSignature.SignatureType, nil
			}
		}
	}
	return "", fmt.Errorf("unsupported jwt key type %q", keyType)
}

func ValidateSignatureKeyType(signatureType SignatureType, keyType string) (kms.KeyType, error) {
	for _, supportedSignature := range signatureTypes {
		if supportedSignature.SignatureType == signatureType {
			return matchKeyType(keyType, supportedSignature.SupportedKeyTypes...)
		}
	}

	return "", fmt.Errorf("%s signature type currently not supported", signatureType)
}

func SignatureTypesSupportedKeyType(keyType kms.KeyType) []SignatureType {
	var result []SignatureType

	for _, supportedSignature := range signatureTypes {
		for _, supportedKeyType := range supportedSignature.SupportedKeyTypes {
			if supportedKeyType == keyType {
				result = append(result, supportedSignature.SignatureType)
			}
		}
	}

	return result
}

func matchKeyType(keyType string, types ...kms.KeyType) (kms.KeyType, error) {
	if keyType == "" && len(types) == 1 {
		return types[0], nil
	}

	var keyTypesNames []string

	for _, possibleType := range types {
		keyTypesNames = append(keyTypesNames, string(possibleType))

		if strings.EqualFold(keyType, string(possibleType)) {
			return possibleType, nil
		}
	}

	if keyType == "" && len(types) > 1 {
		return "", fmt.Errorf("key type should have one of the values %s", strings.Join(keyTypesNames, ","))
	}

	return "", fmt.Errorf("not supported key type %s, should have one of the values %s", keyType,
		strings.Join(keyTypesNames, ","))
}

func matchKeyTypes(keyTypes1 []kms.KeyType, keyTypes2 []kms.KeyType) bool {
	for _, type1 := range keyTypes1 {
		for _, type2 := range keyTypes2 {
			if type1 == type2 {
				return true
			}
		}
	}
	return false
}
