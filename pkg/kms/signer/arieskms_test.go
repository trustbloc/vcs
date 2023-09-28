/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"errors"
	"reflect"
	"testing"

	mockwrapper "github.com/trustbloc/kms-go/mock/wrapper"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	noopMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/noop"
)

func TestKMSSigner_Alg(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "OK",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &KMSSigner{}
			if got := s.Alg(); got != tt.want {
				t.Errorf("Alg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKMSSigner_Sign(t *testing.T) {
	type fields struct {
		keyHandle interface{}
		signValue []byte
		signErr   error
		bbs       bool
	}
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "BBS SignMulti OK",
			fields: fields{
				keyHandle: nil,
				signValue: []byte("signed"),
				signErr:   nil,
				bbs:       true,
			},
			args: args{
				data: []byte("to sign"),
			},
			want:    []byte("signed"),
			wantErr: false,
		},
		{
			name: "BBS SignMulti Error",
			fields: fields{
				keyHandle: nil,
				signValue: nil,
				signErr:   errors.New("some error"),
				bbs:       true,
			},
			args: args{
				data: []byte("to sign"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Sign OK",
			fields: fields{
				keyHandle: nil,
				signValue: []byte("signed"),
				signErr:   nil,
				bbs:       false,
			},
			args: args{
				data: []byte("to sign"),
			},
			want:    []byte("signed"),
			wantErr: false,
		},
		{
			name: "Sign Error",
			fields: fields{
				keyHandle: nil,
				signValue: nil,
				signErr:   errors.New("some error"),
				bbs:       false,
			},
			args: args{
				data: []byte("to sign"),
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &KMSSigner{
				bbs:     tt.fields.bbs,
				metrics: &noopMetricsProvider.NoMetrics{},
				multiSigner: &mockwrapper.MockFixedKeyCrypto{
					SignVal: tt.fields.signValue,
					SignErr: tt.fields.signErr,
				},
				signer: &mockwrapper.MockFixedKeyCrypto{
					SignVal: tt.fields.signValue,
					SignErr: tt.fields.signErr,
				},
			}

			got, err := s.Sign(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sign() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKMSSigner_textToLines(t *testing.T) {
	type args struct {
		txt string
	}
	tests := []struct {
		name    string
		args    args
		getWant func() [][]byte
	}{
		{
			name: "Simple",
			args: args{
				txt: "abc",
			},
			getWant: func() [][]byte {
				l := make([][]byte, 0)
				l = append(l, []byte("abc"))
				return l
			},
		},
		{
			name: "Two lines",
			args: args{
				txt: "abc\ndef",
			},
			getWant: func() [][]byte {
				l := make([][]byte, 0)
				l = append(l, []byte("abc"))
				l = append(l, []byte("def"))
				return l
			},
		},
		{
			name: "Three lines one empty",
			args: args{
				txt: "abc\n\ndef",
			},
			getWant: func() [][]byte {
				l := make([][]byte, 0)
				l = append(l, []byte("abc"))
				l = append(l, []byte("def"))
				return l
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &KMSSigner{}
			if got := s.textToLines(tt.args.txt); !reflect.DeepEqual(got, tt.getWant()) {
				t.Errorf("textToLines() = %v, want %v", got, tt.getWant())
			}
		})
	}
}

func TestNewKMSSigner(t *testing.T) {
	wantSigner := &mockwrapper.MockFixedKeyCrypto{}

	t.Run("OK", func(t *testing.T) {
		got := NewKMSSigner(wantSigner, vcsverifiable.Ed25519Signature2018, nil)

		want := &KMSSigner{
			signatureType: vcsverifiable.Ed25519Signature2018,
			bbs:           false,
			metrics:       &noopMetricsProvider.NoMetrics{},
			signer:        wantSigner,
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("NewKMSSigner() got = %v, want %v", got, want)
		}
	})

	t.Run("OK BBS", func(t *testing.T) {
		got := NewKMSSignerBBS(wantSigner, vcsverifiable.BbsBlsSignature2020, nil)

		want := &KMSSigner{
			signatureType: vcsverifiable.BbsBlsSignature2020,
			bbs:           true,
			metrics:       &noopMetricsProvider.NoMetrics{},
			signer:        wantSigner,
			multiSigner:   wantSigner,
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("NewKMSSignerBBS() got = %v, want %v", got, want)
		}
	})
}
