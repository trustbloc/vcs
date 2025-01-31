/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"reflect"
	"testing"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vctestutil "github.com/trustbloc/vc-go/crypto-ext/testutil"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

//go:embed testdata/sample_vc.jsonld
var sampleVCJsonLD string //nolint:gochecknoglobals

//go:embed testdata/sample_vc.jwt
var sampleVCJWT string //nolint:gochecknoglobals

//go:embed testdata/sample_vc_expired.jwt
var sampleVCJWTExpired string //nolint:gochecknoglobals

//go:embed testdata/sample_vc_invalid.jwt
var sampleVCJWTInvalid string //nolint:gochecknoglobals

//go:embed testdata/sample_vc.sdjwt
var sampleVCSDJWT string //nolint:gochecknoglobals

func TestValidateCredential(t *testing.T) {
	pubKey, privKey, pkErr := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, pkErr)

	proofCreator, _ := testsupport.NewEd25519Pair(pubKey, privKey, testsupport.AnyPubKeyID)

	type args struct {
		cred                    func(t *testing.T) interface{}
		format                  vcsverifiable.Format
		documentLoader          jsonld.DocumentLoader
		opts                    []verifiable.CredentialOpt
		checkExpiration         bool
		enforceStrictValidation bool
	}
	tests := []struct {
		name      string
		args      args
		want      func(t *testing.T) *verifiable.Credential
		wantErr   bool
		wantErrFn func(t *testing.T, err error)
	}{
		{
			name: "OK JWT",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return sampleVCJWT
				},
				format: vcsverifiable.Jwt,
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
				format: vcsverifiable.Ldp,
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
			name: "OK JSON-LD Strict",
			args: args{
				cred: func(t *testing.T) interface{} {
					mapped := map[string]interface{}{}
					err := json.Unmarshal([]byte(sampleVCJsonLD), &mapped)
					require.NoError(t, err)
					return mapped
				},
				format: vcsverifiable.Ldp,
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
				documentLoader:          testutil.DocumentLoader(t),
				enforceStrictValidation: true,
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
			name: "Fail JSON-LD Strict",
			args: args{
				cred: func(t *testing.T) interface{} {
					mapped := map[string]interface{}{}
					err := json.Unmarshal([]byte(sampleVCJsonLD), &mapped)
					require.NoError(t, err)
					mapped["some_field"] = "some_value"
					return mapped
				},
				format: vcsverifiable.Ldp,
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
				documentLoader:          testutil.DocumentLoader(t),
				enforceStrictValidation: true,
			},
			want: func(_ *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Error invalid format JWT",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return []byte(sampleVCJWT)
				},
				format: vcsverifiable.Jwt,
				opts:   []verifiable.CredentialOpt{},
			},
			want: func(_ *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Error invalid format JSON-LD",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return sampleVCJsonLD
				},
				format: vcsverifiable.Ldp,
				opts:   []verifiable.CredentialOpt{},
			},
			want: func(_ *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Error validation JWT",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return ""
				},
				format: vcsverifiable.Jwt,
				opts:   []verifiable.CredentialOpt{},
			},
			want: func(_ *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Error validation JSON-LD",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return map[string]interface{}{}
				},
				format: vcsverifiable.Ldp,
				opts:   []verifiable.CredentialOpt{},
			},
			want: func(_ *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "expired credentials",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return sampleVCJWTExpired
				},
				format: vcsverifiable.Jwt,
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
				checkExpiration: true,
			},
			want: func(_ *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
			wantErrFn: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "credential expired")
			},
		},
		{
			name: "expired credentials (without expiration check)",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return sampleVCJWTExpired
				},
				format: vcsverifiable.Jwt,
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
				checkExpiration: false,
			},
			want: func(t *testing.T) *verifiable.Credential {
				cred, err := verifiable.ParseCredential([]byte(sampleVCJWTExpired), verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
				require.NoError(t, err)
				return cred
			},
		},
		{
			name: "OK JWT with strict validation",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return sampleVCJWT
				},
				format:                  vcsverifiable.Jwt,
				enforceStrictValidation: true,
				documentLoader:          testutil.DocumentLoader(t),
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
			name: "OK JWS with strict validation",
			args: args{
				cred: func(t *testing.T) interface{} {
					cred, err := verifiable.ParseCredential([]byte(sampleVCJWT), verifiable.WithDisabledProofCheck(),
						verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
					require.NoError(t, err)

					jwsVC, err := cred.CreateSignedJWTVC(
						false, verifiable.EdDSA, proofCreator,
						cred.Contents().Issuer.ID+"#keys-1")
					require.NoError(t, err)

					jws, err := jwsVC.ToJWTString()
					require.NoError(t, err)

					return jws
				},
				format:                  vcsverifiable.Jwt,
				enforceStrictValidation: true,
				documentLoader:          testutil.DocumentLoader(t),
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
			},
			want: func(t *testing.T) *verifiable.Credential {
				cred, err := verifiable.ParseCredential([]byte(sampleVCJWT), verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
				require.NoError(t, err)

				jwsCred, err := cred.CreateSignedJWTVC(false,
					verifiable.EdDSA, proofCreator, cred.Contents().Issuer.ID+"#keys-1")
				require.NoError(t, err)

				return jwsCred
			},
			wantErr: false,
		},
		{
			name: "Error JWT with strict validation",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return sampleVCJWTInvalid
				},
				format:                  vcsverifiable.Jwt,
				enforceStrictValidation: true,
				documentLoader:          testutil.DocumentLoader(t),
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
			},
			want: func(_ *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "OK SDJWT with strict validation",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return sampleVCSDJWT
				},
				format:                  vcsverifiable.Jwt,
				enforceStrictValidation: true,
				documentLoader:          testutil.DocumentLoader(t),
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
			},
			want: func(t *testing.T) *verifiable.Credential {
				cred, err := verifiable.ParseCredential([]byte(sampleVCSDJWT), verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
				require.NoError(t, err)
				return cred
			},
			wantErr: false,
		},
		{
			name: "Error SDJWT with strict validation",
			args: args{
				cred: func(t *testing.T) interface{} {
					cred, err := verifiable.ParseCredential([]byte(sampleVCJWT), verifiable.WithDisabledProofCheck(),
						verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
					require.NoError(t, err)

					cred.SetCustomField("referenceNumber", "11223")

					sdjwt, err := cred.MakeSDJWT(vctestutil.NewEd25519Signer(privKey),
						cred.Contents().Issuer.ID+"#keys-1")
					require.NoError(t, err)

					return sdjwt
				},
				format:                  vcsverifiable.Jwt,
				enforceStrictValidation: true,
				documentLoader:          testutil.DocumentLoader(t),
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
			},
			want: func(_ *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateCredential(
				context.TODO(),
				tt.args.cred(t),
				[]vcsverifiable.Format{
					tt.args.format,
				},
				tt.args.checkExpiration,
				tt.args.enforceStrictValidation,
				tt.args.documentLoader,
				tt.args.opts...,
			)
			if err != nil && tt.wantErrFn != nil {
				tt.wantErrFn(t, err)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			wantVC := tt.want(t)

			gotObj, err := got.ToUniversalForm()
			require.NoError(t, err)

			wantVCObj, err := wantVC.ToUniversalForm()
			require.NoError(t, err)

			if !reflect.DeepEqual(gotObj, wantVCObj) {
				t.Errorf("ValidateCredential() got = %v, want %v", got, wantVC)
			}
		})
	}
}

func Test_validateSDJWTCredential(t *testing.T) {
	type args struct {
		getCredential func() *verifiable.Credential
	}
	tests := []struct {
		name           string
		args           args
		wantCredential func() *verifiable.Credential
		wantErr        bool
	}{
		{
			name: "OK",
			args: args{
				getCredential: func() *verifiable.Credential {
					cred, err := verifiable.ParseCredential([]byte(sampleVCSDJWT), verifiable.WithDisabledProofCheck(),
						verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
					require.NoError(t, err)
					return cred
				},
			},
			wantCredential: func() *verifiable.Credential {
				cred, err := verifiable.ParseCredential([]byte(sampleVCSDJWT), verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
				require.NoError(t, err)
				return cred
			},
			wantErr: false,
		},
		{
			name: "Error validate",
			args: args{
				getCredential: func() *verifiable.Credential {
					cred, err := verifiable.ParseCredential([]byte(sampleVCJWT), verifiable.WithDisabledProofCheck(),
						verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
					require.NoError(t, err)

					cred.SetCustomField("referenceNumber", "11223")

					return cred
				},
			},
			wantCredential: func() *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Error create display credential",
			args: args{
				getCredential: func() *verifiable.Credential {
					cred, err := verifiable.ParseCredential([]byte(sampleVCSDJWT), verifiable.WithDisabledProofCheck(),
						verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)))
					require.NoError(t, err)

					cred.JWTEnvelope.JWT = "abc"

					return cred
				},
			},
			wantCredential: func() *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential := tt.args.getCredential()
			documentLoader := testutil.DocumentLoader(t)
			got, err := validateSDJWTCredential(tt.args.getCredential(), documentLoader)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSDJWTCredential(%v, %v) err %s", credential, documentLoader, err.Error())
			}

			assert.Equalf(t, tt.wantCredential(), got, "validateSDJWTCredential(%v, %v)", credential, documentLoader)
		})
	}
}
