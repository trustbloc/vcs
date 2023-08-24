/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import (
	"reflect"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
)

func TestNewSigner(t *testing.T) {
	type args struct {
		keyID        string
		jwsAlgorithm string
		signer       signer
	}
	tests := []struct {
		name string
		args args
		want *Signer
	}{
		{
			name: "OK",
			args: args{
				keyID:        "did:trustbloc:abc#key1",
				jwsAlgorithm: "EdDSA",
				signer:       &mockSigner{},
			},
			want: &Signer{
				keyID:        "did:trustbloc:abc#key1",
				jwsAlgorithm: "EdDSA",
				signer:       &mockSigner{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewSigner(tt.args.keyID, tt.args.jwsAlgorithm, tt.args.signer); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Headers(t *testing.T) {
	type fields struct {
		keyID        string
		jwsAlgorithm string
		signer       signer
	}
	tests := []struct {
		name   string
		fields fields
		want   jose.Headers
	}{
		{
			name: "OK",
			fields: fields{
				keyID:        "did:trustbloc:abc#key1",
				jwsAlgorithm: "EdDSA",
				signer:       &mockSigner{},
			},
			want: jose.Headers{
				jose.HeaderKeyID:     "did:trustbloc:abc#key1",
				jose.HeaderAlgorithm: "EdDSA",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				keyID:        tt.fields.keyID,
				jwsAlgorithm: tt.fields.jwsAlgorithm,
				signer:       tt.fields.signer,
			}
			if got := s.Headers(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Headers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Sign(t *testing.T) {
	type fields struct {
		keyID        string
		jwsAlgorithm string
		signer       signer
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
			name: "OK",
			fields: fields{
				keyID:        "did:trustbloc:abc#key1",
				jwsAlgorithm: "EdDSA",
				signer:       &mockSigner{},
			},
			args: args{
				data: []byte("abc"),
			},
			want:    []byte("abc"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				keyID:        tt.fields.keyID,
				jwsAlgorithm: tt.fields.jwsAlgorithm,
				signer:       tt.fields.signer,
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

type mockSigner struct{}

func (ms *mockSigner) Sign(data []byte) ([]byte, error) {
	return data, nil
}
