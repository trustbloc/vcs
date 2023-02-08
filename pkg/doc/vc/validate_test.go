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

func TestValidateCredential(t *testing.T) {
	type args struct {
		cred   func(t *testing.T) interface{}
		format vcsverifiable.Format
		opts   []verifiable.CredentialOpt
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
					return "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjE1Nzc5MDY2MDQsImlhdCI6MTI2MjM3MzgwNCwiaXNzIjoiZGlkOmV4YW1wbGU6NzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIiwianRpIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzE4NzIiLCJuYmYiOjEyNjIzNzM4MDQsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiLCJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L2Jicy92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwidW5pdmVyc2l0eSI6Ik1JVCJ9LCJpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsIm5hbWUiOiJKYXlkZW4gRG9lIiwic3BvdXNlIjoiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyMC0wMS0wMVQxOToyMzoyNFoiLCJpZCI6Imh0dHA6Ly9leGFtcGxlLmVkdS9jcmVkZW50aWFscy8xODcyIiwiaXNzdWFuY2VEYXRlIjoiMjAxMC0wMS0wMVQxOToyMzoyNFoiLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYiLCJuYW1lIjoiRXhhbXBsZSBVbml2ZXJzaXR5In0sInJlZmVyZW5jZU51bWJlciI6OC4zMjk0ODQ3ZSswNywidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl19fQ." // nolint
				},
				format: vcsverifiable.Jwt,
				opts: []verifiable.CredentialOpt{
					verifiable.WithDisabledProofCheck(),
					verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
			},
			want: func(t *testing.T) *verifiable.Credential {
				return nil
			},
			wantErr: true,
			wantErrFn: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "invalid-value[credential]: credential expired")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateCredential(tt.args.cred(t), []vcsverifiable.Format{tt.args.format}, tt.args.opts...)
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
