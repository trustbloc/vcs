/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
)

func TestProfileStore_ValidateVCFormat(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		err := vc.ValidateVCFormat("jwt_vc")
		require.NoError(t, err)

		err = vc.ValidateVCFormat("ldp_vc")
		require.NoError(t, err)
	})

	t.Run("Fail", func(t *testing.T) {
		err := vc.ValidateVCFormat("fail")
		require.Error(t, err)
	})
}

func TestProfileStore_ValidateVCSignatureAlgorithm(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		validSignatureTypes := []string{"EdDSA",
			"ES256k",
			"ES256",
			"ES384",
			"PS256",
		}

		for _, sigType := range validSignatureTypes {
			stype, err := vc.ValidateVCSignatureAlgorithm("jwt_vc", sigType)
			require.NoError(t, err)
			require.Equal(t, strings.ToLower(sigType), strings.ToLower(stype.Name()))
		}

		validSignatureTypes = []string{
			"Ed25519Signature2018",
			"Ed25519Signature2020",
			"EcdsaSecp256k1Signature2019",
			"BbsBlsSignature2020",
			"JsonWebSignature2020",
		}

		for _, sigType := range validSignatureTypes {
			stype, err := vc.ValidateVCSignatureAlgorithm("ldp_vc", sigType)
			require.NoError(t, err)
			require.Equal(t, sigType, stype.Name())
		}
	})

	t.Run("Fail", func(t *testing.T) {
		_, err := vc.ValidateVCSignatureAlgorithm("fail", "fail")
		require.Error(t, err)
	})

	t.Run("Fail 2", func(t *testing.T) {
		_, err := vc.ValidateVCSignatureAlgorithm("ldp_vc", "fail")
		require.Error(t, err)
	})
}

func TestCrypto_ValidateSignatureKeyType(t *testing.T) {
	t.Run("test success with empty type", func(t *testing.T) {
		signatures := []vc.SignatureType{
			vc.Ed25519Signature2018,
			vc.Ed25519Signature2020,
			vc.BbsBlsSignature2020,
			vc.EcdsaSecp256k1Signature2019,
			vc.EdDSA,
			vc.ES256,
			vc.ES384,
			vc.PS256,
		}

		for _, signature := range signatures {
			_, err := vc.ValidateSignatureKeyType(signature, "")
			require.NoError(t, err)
		}
	})

	t.Run("test success with specific type", func(t *testing.T) {
		signatures := []vc.SignatureType{
			vc.Ed25519Signature2018,
			vc.Ed25519Signature2020,
			vc.EdDSA,
		}

		for _, signature := range signatures {
			_, err := vc.ValidateSignatureKeyType(signature, "ED25519")
			require.NoError(t, err)
		}
	})

	t.Run("unsupported yet", func(t *testing.T) {
		signatures := []vc.SignatureType{
			"some-new-type",
		}

		for _, signature := range signatures {
			_, err := vc.ValidateSignatureKeyType(signature, "")
			require.Contains(t, err.Error(), "signature type currently not supported")
		}
	})

	t.Run("key type missed", func(t *testing.T) {
		signatures := []vc.SignatureType{
			vc.JSONWebSignature2020,
		}

		for _, signature := range signatures {
			_, err := vc.ValidateSignatureKeyType(signature, "")
			require.Contains(t, err.Error(), "key type should have one of the values")
		}
	})

	t.Run("not supported key type", func(t *testing.T) {
		signatures := []vc.SignatureType{
			vc.Ed25519Signature2018,
		}

		for _, signature := range signatures {
			_, err := vc.ValidateSignatureKeyType(signature, "ECDSAP384DER")
			require.Contains(t, err.Error(), "not supported key type ECDSAP384DER")
		}
	})
}
