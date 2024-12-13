/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vp_test

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/doc/vp"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

//go:embed testdata/sample_vp.jsonld
var sampleVPJsonLD string //nolint:gochecknoglobals

//go:embed testdata/sample_vp.jwt
var sampleVPJWT string //nolint:gochecknoglobals

func TestValidatePresentation(t *testing.T) {
	type args struct {
		cred   func(t *testing.T) interface{}
		format vcsverifiable.Format
		opts   []verifiable.PresentationOpt
	}
	tests := []struct {
		name    string
		args    args
		want    func(t *testing.T) *verifiable.Presentation
		wantErr bool
	}{
		{
			name: "OK JWT",
			args: args{
				cred: func(t *testing.T) interface{} {
					return sampleVPJWT
				},
				format: vcsverifiable.Jwt,
				opts: []verifiable.PresentationOpt{
					verifiable.WithPresDisabledProofCheck(),
					verifiable.WithPresJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
			},
			want: func(t *testing.T) *verifiable.Presentation {
				presentation, err := verifiable.ParsePresentation([]byte(sampleVPJWT),
					verifiable.WithPresDisabledProofCheck(),
					verifiable.WithPresJSONLDDocumentLoader(testutil.DocumentLoader(t)))
				require.NoError(t, err)
				return presentation
			},
			wantErr: false,
		},
		{
			name: "OK JSON-LD",
			args: args{
				cred: func(t *testing.T) interface{} {
					mapped := map[string]interface{}{}
					err := json.Unmarshal([]byte(sampleVPJsonLD), &mapped)
					require.NoError(t, err)
					return mapped
				},
				format: vcsverifiable.Ldp,
				opts: []verifiable.PresentationOpt{
					verifiable.WithPresDisabledProofCheck(),
					verifiable.WithPresJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				},
			},
			want: func(t *testing.T) *verifiable.Presentation {
				presentation, err := verifiable.ParsePresentation([]byte(sampleVPJsonLD),
					verifiable.WithPresDisabledProofCheck(),
					verifiable.WithPresJSONLDDocumentLoader(testutil.DocumentLoader(t)))
				require.NoError(t, err)
				return presentation
			},
			wantErr: false,
		},
		{
			name: "Error invalid format JWT",
			args: args{
				cred: func(t *testing.T) interface{} {
					return []byte(sampleVPJWT)
				},
				format: vcsverifiable.Jwt,
				opts:   []verifiable.PresentationOpt{},
			},
			want: func(_ *testing.T) *verifiable.Presentation {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Error invalid format JSON-LD",
			args: args{
				cred: func(_ *testing.T) interface{} {
					return sampleVPJsonLD
				},
				format: vcsverifiable.Ldp,
				opts:   []verifiable.PresentationOpt{},
			},
			want: func(t *testing.T) *verifiable.Presentation {
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
				opts:   []verifiable.PresentationOpt{},
			},
			want: func(t *testing.T) *verifiable.Presentation {
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
				opts:   []verifiable.PresentationOpt{},
			},
			want: func(t *testing.T) *verifiable.Presentation {
				return nil
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vp.ValidatePresentation(tt.args.cred(t), []vcsverifiable.Format{tt.args.format}, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePresentation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			wantVC := tt.want(t)
			if !reflect.DeepEqual(got, wantVC) {
				t.Errorf("ValidateCredential() got = %v, want %v", got, wantVC)
			}
		})
	}
}
