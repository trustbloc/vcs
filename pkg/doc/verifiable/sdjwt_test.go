package verifiable

import (
	"reflect"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

func TestIsSDJWT(t *testing.T) {
	type args struct {
		jwt string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "OK",
			args: args{
				jwt: jwtHeader +
					jwtSeparator +
					jwtPayload +
					jwtSeparator +
					jwtSignature +
					common.CombinedFormatSeparator +
					disclosureA +
					common.CombinedFormatSeparator +
					disclosureB,
			},
			want: true,
		},
		{
			name: "Regular JWS",
			args: args{
				jwt: jwtHeader +
					jwtSeparator +
					jwtPayload +
					jwtSeparator +
					jwtSignature,
			},
			want: false,
		},
		{
			name: "Regular JWT",
			args: args{
				jwt: jwtHeader +
					jwtSeparator +
					jwtPayload +
					jwtSeparator,
			},
			want: false,
		},
		{
			name: "String with DisclosureSeparator",
			args: args{
				jwt: "aaa" + common.CombinedFormatSeparator,
			},
			want: false,
		},
		{
			name: "Error invalid payload",
			args: args{
				jwt: jwtHeader +
					jwtSeparator +
					"    " +
					common.CombinedFormatSeparator,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSDJWT(tt.args.jwt); got != tt.want {
				t.Errorf("IsSDJWT() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnQuote(t *testing.T) {
	type args struct {
		s []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "OK empty",
			args: args{
				s: []byte(""),
			},
			want: []byte(""),
		},
		{
			name: "OK not wrapped in quotes",
			args: args{
				s: []byte("123"),
			},
			want: []byte("123"),
		},
		{
			name: "OK wrapped in quotes",
			args: args{
				s: []byte(`"123"`),
			},
			want: []byte("123"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UnQuote(tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnQuote() = %v, want %v", got, tt.want)
			}
		})
	}
}
