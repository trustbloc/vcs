/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
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
		getCrypto func() crypto
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
				getCrypto: func() crypto {
					return &mockcrypto.Crypto{
						BBSSignValue: []byte("signed"),
						BBSSignErr:   nil,
					}
				},
				bbs: true,
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
				getCrypto: func() crypto {
					return &mockcrypto.Crypto{
						BBSSignValue: nil,
						BBSSignErr:   errors.New("some error"),
					}
				},
				bbs: true,
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
				getCrypto: func() crypto {
					return &mockcrypto.Crypto{
						SignValue: []byte("signed"),
						SignErr:   nil,
					}
				},
				bbs: false,
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
				getCrypto: func() crypto {
					return &mockcrypto.Crypto{
						SignValue: nil,
						SignErr:   errors.New("some error"),
					}
				},
				bbs: false,
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
				keyHandle: tt.fields.keyHandle,
				crypto:    tt.fields.getCrypto(),
				bbs:       tt.fields.bbs,
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
	type args struct {
		keyManager    kms.KeyManager
		c             crypto
		creator       string
		signatureType vcsverifiable.SignatureType
	}
	tests := []struct {
		name    string
		args    args
		want    *KMSSigner
		wantErr bool
	}{
		{
			name: "OK",
			args: args{
				keyManager: &mockkms.KeyManager{
					GetKeyValue: &keyset.Handle{},
					GetKeyErr:   nil,
				},
				c:             &mockcrypto.Crypto{},
				creator:       "example#key1",
				signatureType: vcsverifiable.Ed25519Signature2018,
			},
			want: &KMSSigner{
				keyHandle: &keyset.Handle{},
				crypto:    &mockcrypto.Crypto{},
				bbs:       false,
			},
			wantErr: false,
		},
		{
			name: "OK BBS",
			args: args{
				keyManager: &mockkms.KeyManager{
					GetKeyValue: &keyset.Handle{},
					GetKeyErr:   nil,
				},
				c:             &mockcrypto.Crypto{},
				creator:       "example#key1",
				signatureType: vcsverifiable.BbsBlsSignature2020,
			},
			want: &KMSSigner{
				keyHandle: &keyset.Handle{},
				crypto:    &mockcrypto.Crypto{},
				bbs:       true,
			},
			wantErr: false,
		},
		{
			name: "Error invalid creator",
			args: args{
				keyManager: &mockkms.KeyManager{
					GetKeyValue: &keyset.Handle{},
					GetKeyErr:   nil,
				},
				c:             &mockcrypto.Crypto{},
				creator:       "key1",
				signatureType: vcsverifiable.BbsBlsSignature2020,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Error key manager",
			args: args{
				keyManager: &mockkms.KeyManager{
					GetKeyValue: nil,
					GetKeyErr:   errors.New("some error"),
				},
				c:             &mockcrypto.Crypto{},
				creator:       "example#key1",
				signatureType: vcsverifiable.BbsBlsSignature2020,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKMSSigner(tt.args.keyManager, tt.args.c, tt.args.creator, tt.args.signatureType)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKMSSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKMSSigner() got = %v, want %v", got, tt.want)
			}
		})
	}
}
