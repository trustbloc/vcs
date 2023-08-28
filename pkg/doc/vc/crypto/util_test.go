/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
)

func TestGetVerificationMethodFromProof(t *testing.T) {
	type args struct {
		proof verifiable.Proof
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "OK",
			args: args{
				proof: map[string]interface{}{
					VerificationMethod: "VerificationMethod",
				},
			},
			want:    "VerificationMethod",
			wantErr: false,
		},
		{
			name: "Error no VerificationMethod",
			args: args{
				proof: map[string]interface{}{},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Error VerificationMethod not a string",
			args: args{
				proof: map[string]interface{}{
					VerificationMethod: 1,
				},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetVerificationMethodFromProof(tt.args.proof)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetVerificationMethodFromProof() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetVerificationMethodFromProof() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateProofKey(t *testing.T) {
	type args struct {
		proof         verifiable.Proof
		key           string
		expectedValue string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "OK",
			args: args{
				proof: map[string]interface{}{
					Challenge: Challenge,
				},
				key:           Challenge,
				expectedValue: Challenge,
			},
			wantErr: false,
		},
		{
			name: "Error key does not exist",
			args: args{
				proof:         map[string]interface{}{},
				key:           Challenge,
				expectedValue: Challenge,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateProofKey(tt.args.proof, tt.args.key, tt.args.expectedValue); (err != nil) != tt.wantErr {
				t.Errorf("ValidateProofData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateProof(t *testing.T) {
	type args struct {
		proof              verifiable.Proof
		verificationMethod string
		didDoc             *did.Doc
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "OK",
			args: args{
				proof: map[string]interface{}{
					Purpose: AssertionMethod,
				},
				verificationMethod: VerificationMethod,
				didDoc: &did.Doc{
					AssertionMethod: []did.Verification{
						{
							VerificationMethod: did.VerificationMethod{
								ID: VerificationMethod,
							},
							Relationship: 0,
							Embedded:     false,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Error purpose missed",
			args: args{
				proof:  map[string]interface{}{},
				didDoc: &did.Doc{},
			},
			wantErr: true,
		},
		{
			name: "Error purpose not a string",
			args: args{
				proof: map[string]interface{}{
					Purpose: 123,
				},
				didDoc: &did.Doc{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateProof(tt.args.proof, tt.args.verificationMethod, tt.args.didDoc); (err != nil) != tt.wantErr {
				t.Errorf("ValidateProofPurpose() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
