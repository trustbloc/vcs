/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapFormat(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		resp, err := MapFormatToOIDCFormat(Jwt)
		assert.NoError(t, err)
		assert.NotEmpty(t, resp)
	})

	t.Run("fail", func(t *testing.T) {
		resp, err := MapFormatToOIDCFormat("random")
		assert.ErrorContains(t, err, "unsupported vc mapping for format: random")
		assert.Empty(t, resp)
	})
}

func TestValidateFormat(t *testing.T) {
	type args struct {
		data    interface{}
		formats []Format
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "OK JWT",
			args: args{
				data:    "some data",
				formats: []Format{Jwt},
			},
			want:    []byte("some data"),
			wantErr: false,
		},
		{
			name: "Error JWT",
			args: args{
				data:    "some data",
				formats: []Format{Ldp},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "OK LDP",
			args: args{
				data:    struct{ Key string }{Key: "some data"},
				formats: []Format{Ldp},
			},
			want:    []byte(`{"Key":"some data"}`),
			wantErr: false,
		},
		{
			name: "Error LDP",
			args: args{
				data:    struct{ Key string }{Key: "some data"},
				formats: []Format{Jwt},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Error invalid data",
			args: args{
				data:    func() {},
				formats: []Format{Ldp},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateFormat(tt.args.data, tt.args.formats)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateFormat() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isFormatSupported(t *testing.T) {
	type args struct {
		format           Format
		supportedFormats []Format
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "True",
			args: args{
				format:           Jwt,
				supportedFormats: []Format{Jwt},
			},
			want: true,
		},
		{
			name: "False",
			args: args{
				format:           Jwt,
				supportedFormats: []Format{Ldp},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFormatSupported(tt.args.format, tt.args.supportedFormats); got != tt.want {
				t.Errorf("isFormatSupported() = %v, want %v", got, tt.want)
			}
		})
	}
}
