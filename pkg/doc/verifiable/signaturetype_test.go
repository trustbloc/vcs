/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
)

func TestProfileStore_ValidateVCSignatureAlgorithm(t *testing.T) {
	supportedKeyTypes := []kms.KeyType{
		kms.ED25519Type,
		kms.X25519ECDHKWType,
		kms.ECDSASecp256k1TypeIEEEP1363,
		kms.ECDSAP256TypeDER,
		kms.ECDSAP384TypeDER,
		kms.RSAPS256Type,
		kms.BLS12381G2Type,
	}

	t.Run("Success", func(t *testing.T) {
		validSignatureTypes := []string{"EdDSA",
			"ES256k",
			"ES256",
			"ES384",
			"PS256",
		}

		for _, sigType := range validSignatureTypes {
			stype, err := ValidateSignatureAlgorithm(Jwt, sigType, supportedKeyTypes)
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
			stype, err := ValidateSignatureAlgorithm(Ldp, sigType, supportedKeyTypes)
			require.NoError(t, err)
			require.Equal(t, sigType, stype.Name())
		}
	})

	t.Run("Fail", func(t *testing.T) {
		_, err := ValidateSignatureAlgorithm("fail", "fail", supportedKeyTypes)
		require.Error(t, err)
	})

	t.Run("Fail 2", func(t *testing.T) {
		_, err := ValidateSignatureAlgorithm("ldp_vc", "fail", supportedKeyTypes)
		require.Error(t, err)
	})
}

func TestCrypto_ValidateSignatureKeyType(t *testing.T) {
	t.Run("test success with empty type", func(t *testing.T) {
		signatures := []SignatureType{
			Ed25519Signature2018,
			Ed25519Signature2020,
			BbsBlsSignature2020,
			EdDSA,
			ES256,
			ES384,
			PS256,
		}

		for _, signature := range signatures {
			_, err := ValidateSignatureKeyType(signature, "")
			require.NoError(t, err)
		}
	})

	t.Run("test success with specific type", func(t *testing.T) {
		signatures := []SignatureType{
			Ed25519Signature2018,
			Ed25519Signature2020,
			EdDSA,
		}

		for _, signature := range signatures {
			_, err := ValidateSignatureKeyType(signature, "ED25519")
			require.NoError(t, err)
		}
	})

	t.Run("unsupported yet", func(t *testing.T) {
		signatures := []SignatureType{
			"some-new-type",
		}

		for _, signature := range signatures {
			_, err := ValidateSignatureKeyType(signature, "")
			require.Contains(t, err.Error(), "signature type currently not supported")
		}
	})

	t.Run("key type missed", func(t *testing.T) {
		signatures := []SignatureType{
			JSONWebSignature2020,
		}

		for _, signature := range signatures {
			_, err := ValidateSignatureKeyType(signature, "")
			require.Contains(t, err.Error(), "key type should have one of the values")
		}
	})

	t.Run("not supported key type", func(t *testing.T) {
		signatures := []SignatureType{
			Ed25519Signature2018,
		}

		for _, signature := range signatures {
			_, err := ValidateSignatureKeyType(signature, "ECDSAP384DER")
			require.Contains(t, err.Error(), "not supported key type ECDSAP384DER")
		}
	})
}

func TestGetSignatureTypesByKeyTypeFormat(t *testing.T) {
	sigTypes := GetSignatureTypesByKeyTypeFormat(kms.ED25519Type, Jwt)
	require.Len(t, sigTypes, 1)
	require.Equal(t, EdDSA, sigTypes[0])

	sigTypes = GetSignatureTypesByKeyTypeFormat(kms.ED25519Type, Ldp)
	require.Len(t, sigTypes, 3)
	require.Contains(t, sigTypes, Ed25519Signature2018)
	require.Contains(t, sigTypes, Ed25519Signature2020)
	require.Contains(t, sigTypes, JSONWebSignature2020)
}

func TestGetSignatureTypeByName(t *testing.T) {
	type args struct {
		signatureType string
	}
	tests := []struct {
		name    string
		args    args
		want    SignatureType
		wantErr bool
	}{
		{
			name: "OK EdDSA",
			args: args{
				signatureType: string(EdDSA),
			},
			want:    EdDSA,
			wantErr: false,
		},
		{
			name: "OK ES256K",
			args: args{
				signatureType: string(ES256K),
			},
			want:    ES256K,
			wantErr: false,
		},
		{
			name: "OK ES256",
			args: args{
				signatureType: string(ES256),
			},
			want:    ES256,
			wantErr: false,
		},
		{
			name: "OK ES384",
			args: args{
				signatureType: string(ES384),
			},
			want:    ES384,
			wantErr: false,
		},
		{
			name: "OK PS256",
			args: args{
				signatureType: string(PS256),
			},
			want:    PS256,
			wantErr: false,
		},
		{
			name: "OK Ed25519Signature2018",
			args: args{
				signatureType: string(Ed25519Signature2018),
			},
			want:    Ed25519Signature2018,
			wantErr: false,
		},
		{
			name: "OK Ed25519Signature2020",
			args: args{
				signatureType: string(Ed25519Signature2020),
			},
			want:    Ed25519Signature2020,
			wantErr: false,
		},
		{
			name: "OK EcdsaSecp256k1Signature2019",
			args: args{
				signatureType: string(EcdsaSecp256k1Signature2019),
			},
			want:    EcdsaSecp256k1Signature2019,
			wantErr: false,
		},
		{
			name: "OK BbsBlsSignature2020",
			args: args{
				signatureType: string(BbsBlsSignature2020),
			},
			want:    BbsBlsSignature2020,
			wantErr: false,
		},
		{
			name: "OK JSONWebSignature2020",
			args: args{
				signatureType: string(JSONWebSignature2020),
			},
			want:    JSONWebSignature2020,
			wantErr: false,
		},
		{
			name: "Error",
			args: args{
				signatureType: "",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetSignatureTypeByName(tt.args.signatureType)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSignatureTypeByName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetSignatureTypeByName() got = %v, want %v", got, tt.want)
			}
		})
	}
}
