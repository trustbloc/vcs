/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc_test

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

//go:embed testdata/sample_vc.jsonld
var sampleVCJsonLD string //nolint:gochecknoglobals

//go:embed testdata/sample_vc.jwt
var sampleVCJWT string //nolint:gochecknoglobals

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
			stype, err := vc.ValidateSignatureAlgorithm(vc.Jwt, sigType, supportedKeyTypes)
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
			stype, err := vc.ValidateSignatureAlgorithm(vc.Ldp, sigType, supportedKeyTypes)
			require.NoError(t, err)
			require.Equal(t, sigType, stype.Name())
		}
	})

	t.Run("Fail", func(t *testing.T) {
		_, err := vc.ValidateSignatureAlgorithm("fail", "fail", supportedKeyTypes)
		require.Error(t, err)
	})

	t.Run("Fail 2", func(t *testing.T) {
		_, err := vc.ValidateSignatureAlgorithm("ldp_vc", "fail", supportedKeyTypes)
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

func TestValidateCredential(t *testing.T) {
	type args struct {
		cred   func(t *testing.T) interface{}
		format vc.Format
		opts   []verifiable.CredentialOpt
	}
	tests := []struct {
		name    string
		args    args
		want    func(t *testing.T) *verifiable.Credential
		wantErr bool
	}{
		{
			name: "OK JWT",
			args: args{
				cred: func(t *testing.T) interface{} {
					return sampleVCJWT
				},
				format: vc.Jwt,
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
			},
			want: func(t *testing.T) *verifiable.Credential {
				cred, err := verifiable.ParseCredential([]byte(sampleVCJWT), verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
				require.NoError(t, err)
				return cred
			},
			wantErr: false,
		},
		{
			name: "OK JSON-LD",
			args: args{
				cred: func(t *testing.T) interface{} {
					mapped := map[string]interface{}{}
					err := json.Unmarshal([]byte(sampleVCJsonLD), &mapped)
					require.NoError(t, err)
					return mapped
				},
				format: vc.Ldp,
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
			},
			want: func(t *testing.T) *verifiable.Credential {
				cred, err := verifiable.ParseCredential([]byte(sampleVCJsonLD), verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
				require.NoError(t, err)
				return cred
			},
			wantErr: false,
		},
		{
			name: "Error invalid format JWT",
			args: args{
				cred: func(t *testing.T) interface{} {
					return []byte(sampleVCJWT)
				},
				format: vc.Jwt,
				opts:   []verifiable.CredentialOpt{},
			},
			want: func(t *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Error invalid format JSON-LD",
			args: args{
				cred: func(t *testing.T) interface{} {
					return sampleVCJsonLD
				},
				format: vc.Ldp,
				opts:   []verifiable.CredentialOpt{},
			},
			want: func(t *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Error validation JWT",
			args: args{
				cred: func(t *testing.T) interface{} {
					return ""
				},
				format: vc.Jwt,
				opts:   []verifiable.CredentialOpt{},
			},
			want: func(t *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Error validation JSON-LD",
			args: args{
				cred: func(t *testing.T) interface{} {
					return map[string]interface{}{}
				},
				format: vc.Ldp,
				opts:   []verifiable.CredentialOpt{},
			},
			want: func(t *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vc.ValidateCredential(tt.args.cred(t), []vc.Format{tt.args.format}, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			wantVC := tt.want(t)
			if !reflect.DeepEqual(got, wantVC) {
				t.Errorf("ValidateCredential() got = %v, want %v", got, wantVC)
			}
		})
	}
}

func TestGetSignatureTypeByName(t *testing.T) {
	type args struct {
		signatureType string
	}
	tests := []struct {
		name    string
		args    args
		want    vc.SignatureType
		wantErr bool
	}{
		{
			name: "OK EdDSA",
			args: args{
				signatureType: string(vc.EdDSA),
			},
			want:    vc.EdDSA,
			wantErr: false,
		},
		{
			name: "OK ES256K",
			args: args{
				signatureType: string(vc.ES256K),
			},
			want:    vc.ES256K,
			wantErr: false,
		},
		{
			name: "OK ES256",
			args: args{
				signatureType: string(vc.ES256),
			},
			want:    vc.ES256,
			wantErr: false,
		},
		{
			name: "OK ES384",
			args: args{
				signatureType: string(vc.ES384),
			},
			want:    vc.ES384,
			wantErr: false,
		},
		{
			name: "OK PS256",
			args: args{
				signatureType: string(vc.PS256),
			},
			want:    vc.PS256,
			wantErr: false,
		},
		{
			name: "OK Ed25519Signature2018",
			args: args{
				signatureType: string(vc.Ed25519Signature2018),
			},
			want:    vc.Ed25519Signature2018,
			wantErr: false,
		},
		{
			name: "OK Ed25519Signature2020",
			args: args{
				signatureType: string(vc.Ed25519Signature2020),
			},
			want:    vc.Ed25519Signature2020,
			wantErr: false,
		},
		{
			name: "OK EcdsaSecp256k1Signature2019",
			args: args{
				signatureType: string(vc.EcdsaSecp256k1Signature2019),
			},
			want:    vc.EcdsaSecp256k1Signature2019,
			wantErr: false,
		},
		{
			name: "OK BbsBlsSignature2020",
			args: args{
				signatureType: string(vc.BbsBlsSignature2020),
			},
			want:    vc.BbsBlsSignature2020,
			wantErr: false,
		},
		{
			name: "OK JSONWebSignature2020",
			args: args{
				signatureType: string(vc.JSONWebSignature2020),
			},
			want:    vc.JSONWebSignature2020,
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
			got, err := vc.GetSignatureTypeByName(tt.args.signatureType)
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
