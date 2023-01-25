/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"reflect"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

const (
	jwtHeader  = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp0cnVzdGJsb2M6YWJjI2tleTEifQ"
	jwtPayload = "eyJpYXQiOjE2NzM5ODc1NDcsImlzcyI6ImRpZDpleGFtcGxlOjc2ZTEyZWM3MT" +
		"JlYmM2ZjFjMjIxZWJmZWIxZiIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLmVkdS9jcmVkZW50a" +
		"WFscy8xODcyIiwibmJmIjoxNjczOTg3NTQ3LCJzdWIiOiJkaWQ6ZXhhbXBsZTplYmZlYjFm" +
		"NzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy5" +
		"3My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2" +
		"QiOlsiVklMLXlXZHlZX3hNbk5icEJvbHRrcnlBOFZESVFVYllLd2dQaHVEUEx1ZyIsIkxDL" +
		"Ug0R2N4UG1OdGN5VWNiSGFDbTlEUDFnZDROYXJsZ2RiUFc4ZEVvZ2siLCJlbHVRRFVtbHpw" +
		"M19naU9uRFVRVk1WLWpWM1hMNXVIck1BNzRROXI0dVF3Il0sIl9zZF9hbGciOiJzaGEtMjU" +
		"2IiwiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEifSwiZm" +
		"lyc3RfbmFtZSI6IkZpcnN0IG5hbWUiLCJpZCI6Imh0dHA6Ly9leGFtcGxlLmVkdS9jcmVkZ" +
		"W50aWFscy8xODcyIiwiaW5mbyI6IkluZm8iLCJpc3N1YW5jZURhdGUiOiIyMDIzLTAxLTE3" +
		"VDIyOjMyOjI3LjQ2ODEwOTgxNyswMjowMCIsImlzc3VlciI6ImRpZDpleGFtcGxlOjc2ZTE" +
		"yZWM3MTJlYmM2ZjFjMjIxZWJmZWIxZiIsImxhc3RfbmFtZSI6Ikxhc3QgbmFtZSIsInR5cG" +
		"UiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9fQ"
	jwtSignature = "PvRYW8-EAG7K4QQL3TV-GNF--vaYIGc3TWJrRSoc2qBCVT5sFkez7FTLv7ia" +
		"e24S2mi2GH5lcxy1dx75LSjOBA"
	disclosureA = "WyJIb01DbEdxLUpRUUZIMUVZZnFCN1FBIiwic3BvdXNlIiwiZGlkOmV4YW1wb" +
		"GU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIl0"
	disclosureB = "WyI5ZDFzTUFYUEVTZkEzaTE0NDNzVTRRIiwiZGVncmVlIix7ImRlZ3JlZSI6I" +
		"k1JVCIsInR5cGUiOiJCYWNoZWxvckRlZ3JlZSJ9XQ"
	disclosureC  = "WyJiekpGY1pYMkYyRjE3XzVsSFU2MjF3IiwibmFtZSIsIkpheWRlbiBEb2UiXQ"
	jwtSeparator = "."
)

func TestValidateFormat(t *testing.T) {
	type args struct {
		data    interface{}
		formats []Format
	}
	tests := []struct {
		name    string
		args    args
		want    *FormatMetadata
		wantErr bool
	}{
		{
			name: "OK JWT signed",
			args: args{
				data:    jwtHeader + jwtSeparator + jwtPayload + jwtSeparator + jwtSignature,
				formats: []Format{Jwt},
			},
			want: &FormatMetadata{
				Data:             []byte(jwtHeader + jwtSeparator + jwtPayload + jwtSeparator + jwtSignature),
				Format:           Jwt,
				SDJWTDisclosures: "",
			},
			wantErr: false,
		},
		{
			name: "OK JWT unsigned",
			args: args{
				data:    jwtHeader + jwtSeparator + jwtPayload + jwtSeparator,
				formats: []Format{Jwt},
			},
			want: &FormatMetadata{
				Data:             []byte(jwtHeader + jwtSeparator + jwtPayload + jwtSeparator),
				Format:           Jwt,
				SDJWTDisclosures: "",
			},
			wantErr: false,
		},
		{
			name: "OK SD-JWT signed",
			args: args{
				data: jwtHeader + jwtSeparator + jwtPayload + jwtSeparator + jwtSignature +
					common.CombinedFormatSeparator +
					disclosureA + common.CombinedFormatSeparator +
					disclosureB + common.CombinedFormatSeparator +
					disclosureC,
				formats: []Format{Jwt},
			},
			want: &FormatMetadata{
				Data:   []byte(jwtHeader + jwtSeparator + jwtPayload + jwtSeparator + jwtSignature),
				Format: Jwt,
				SDJWTDisclosures: disclosureA + common.CombinedFormatSeparator +
					disclosureB + common.CombinedFormatSeparator +
					disclosureC,
			},
			wantErr: false,
		},
		{
			name: "OK SD-JWT unsigned",
			args: args{
				data: jwtHeader + jwtSeparator + jwtPayload + jwtSeparator +
					common.CombinedFormatSeparator +
					disclosureA + common.CombinedFormatSeparator +
					disclosureB + common.CombinedFormatSeparator +
					disclosureC,
				formats: []Format{Jwt},
			},
			want: &FormatMetadata{
				Data:   []byte(jwtHeader + jwtSeparator + jwtPayload + jwtSeparator),
				Format: Jwt,
				SDJWTDisclosures: disclosureA + common.CombinedFormatSeparator +
					disclosureB + common.CombinedFormatSeparator +
					disclosureC,
			},
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
			want: &FormatMetadata{
				Data:   []byte(`{"Key":"some data"}`),
				Format: Ldp,
			},
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
