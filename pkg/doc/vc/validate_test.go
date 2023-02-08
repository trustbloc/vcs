/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

//go:embed testdata/sample_vc.jsonld
var sampleVCJsonLD string //nolint:gochecknoglobals

//go:embed testdata/sample_vc.jwt
var sampleVCJWT string //nolint:gochecknoglobals

//go:embed testdata/sample_vc_expired.jwt
var sampleVCJWTExpired string //nolint:gochecknoglobals

func TestValidateCredential(t *testing.T) {
	type args struct {
		cred            func(t *testing.T) interface{}
		format          vcsverifiable.Format
		opts            []verifiable.CredentialOpt
		checkExpiration bool
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
				cred: func(t *testing.T) interface{} {
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
			name: "Error invalid format JWT",
			args: args{
				cred: func(t *testing.T) interface{} {
					return []byte(sampleVCJWT)
				},
				format: vcsverifiable.Jwt,
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
				format: vcsverifiable.Ldp,
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
				format: vcsverifiable.Jwt,
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
				format: vcsverifiable.Ldp,
				opts:   []verifiable.CredentialOpt{},
			},
			want: func(t *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
		},
		{
			name: "expired credentials",
			args: args{
				cred: func(t *testing.T) interface{} {
					return sampleVCJWTExpired
				},
				format: vcsverifiable.Jwt,
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
				checkExpiration: true,
			},
			want: func(t *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
			wantErrFn: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "invalid-value[credential]: credential expired")
			},
		},
		{
			name: "expired credentials (without expiration check)",
			args: args{
				cred: func(t *testing.T) interface{} {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateCredential(
				tt.args.cred(t),
				[]vcsverifiable.Format{
					tt.args.format,
				},
				tt.args.checkExpiration,
				tt.args.opts...,
			)
			if err != nil && tt.wantErrFn != nil {
				tt.wantErrFn(t, err)
			}
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
