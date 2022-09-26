/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifypresentation

import (
	_ "embed"
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	kmskeytypes "github.com/hyperledger/aries-framework-go/pkg/kms"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/verifier"
)

var (
	//go:embed testdata/valid_vp.jsonld
	sampleVPJsonLD string
)

func TestNew(t *testing.T) {
	type args struct {
		config *Config
	}
	tests := []struct {
		name string
		args args
		want *Service
	}{
		{
			name: "OK",
			args: args{
				config: &Config{
					VDR:            &mockvdr.MockVDRegistry{},
					DocumentLoader: testutil.DocumentLoader(t),
					VcVerifier:     NewMockVcVerifier(gomock.NewController(t)),
				},
			},
			want: &Service{
				vdr:            &mockvdr.MockVDRegistry{},
				documentLoader: testutil.DocumentLoader(t),
				vcVerifier:     NewMockVcVerifier(gomock.NewController(t)),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.config); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_VerifyPresentation(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	signedVP, vdr := testutil.SignedVP(
		t, []byte(sampleVPJsonLD), kmskeytypes.ED25519Type, verifiable.SignatureProofValue, loader, crypto.AssertionMethod)

	type fields struct {
		getVDR        func() vdrapi.Registry
		getVcVerifier func() vcVerifier
	}
	type args struct {
		getPresentation func() *verifiable.Presentation
		profile         *verifier.Profile
		opts            *Options
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []PresentationVerificationCheckResult
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return vdr
				},
				getVcVerifier: func() vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(nil)
					return mockVerifier
				},
			},
			args: args{
				getPresentation: func() *verifiable.Presentation {
					return signedVP
				},
				profile: &verifier.Profile{
					Checks: &verifier.VerificationChecks{
						Presentation: &verifier.PresentationChecks{
							Proof:  true,
							Format: nil,
						},
					},
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: crypto.Challenge,
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "OK no checks",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return nil
				},
				getVcVerifier: func() vcVerifier {
					return nil
				},
			},
			args: args{
				getPresentation: func() *verifiable.Presentation {
					return nil
				},
				profile: &verifier.Profile{
					Checks: &verifier.VerificationChecks{
						Presentation: &verifier.PresentationChecks{
							Proof:  false,
							Format: nil,
						},
					},
				},
				opts: nil,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "Error empty VDR",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &mockvdr.MockVDRegistry{}
				},
				getVcVerifier: func() vcVerifier {
					return nil
				},
			},
			args: args{
				getPresentation: func() *verifiable.Presentation {
					return signedVP
				},
				profile: &verifier.Profile{
					Checks: &verifier.VerificationChecks{
						Presentation: &verifier.PresentationChecks{
							Proof:  true,
							Format: nil,
						},
					},
				},
				opts: nil,
			},
			want: []PresentationVerificationCheckResult{
				{
					Check: "proof",
					Error: "verifiable presentation proof validation error : " +
						"check embedded proof: check linked data proof: resolve DID did:trustblock:abc: " +
						"DID does not exist",
				},
			},
			wantErr: false,
		},
		{
			name: "Error invalid signature",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return vdr
				},
				getVcVerifier: func() vcVerifier {
					return nil
				},
			},
			args: args{
				getPresentation: func() *verifiable.Presentation {
					vp := *signedVP
					vp.Holder = "invalid value"
					return &vp
				},
				profile: &verifier.Profile{
					Checks: &verifier.VerificationChecks{
						Presentation: &verifier.PresentationChecks{
							Proof:  true,
							Format: nil,
						},
					},
				},
				opts: nil,
			},
			want: []PresentationVerificationCheckResult{
				{
					Check: "proof",
					Error: "verifiable presentation proof validation error : check embedded proof: " +
						"check linked data proof: ed25519: invalid signature",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vdr:            tt.fields.getVDR(),
				documentLoader: loader,
				vcVerifier:     tt.fields.getVcVerifier(),
			}
			got, err := s.VerifyPresentation(tt.args.getPresentation(), tt.args.profile, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPresentation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VerifyPresentation() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_parseAndVerifyPresentation(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	signedVP, vdr := testutil.SignedVP(
		t, []byte(sampleVPJsonLD), kmskeytypes.ED25519Type, verifiable.SignatureProofValue, loader, crypto.AssertionMethod)

	type fields struct {
		getVDR        func() vdrapi.Registry
		getVcVerifier func() vcVerifier
	}
	type args struct {
		getVpBytes               func() []byte
		validateCredentialProof  bool
		validateCredentialStatus bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *verifiable.Presentation
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return vdr
				},
				getVcVerifier: func() vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(nil)
					mockVerifier.EXPECT().ValidateVCStatus(
						gomock.Any(),
						gomock.Any()).Times(1).Return(nil)
					return mockVerifier
				},
			},
			args: args{
				getVpBytes: func() []byte {
					b, _ := signedVP.MarshalJSON()
					return b
				},
				validateCredentialProof:  true,
				validateCredentialStatus: true,
			},
			want:    signedVP,
			wantErr: false,
		},
		{
			name: "Error empty VDR",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &mockvdr.MockVDRegistry{}
				},
				getVcVerifier: func() vcVerifier {
					return nil
				},
			},
			args: args{
				getVpBytes: func() []byte {
					b, _ := signedVP.MarshalJSON()
					return b
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Error invalid VP",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return vdr
				},
				getVcVerifier: func() vcVerifier {
					return nil
				},
			},
			args: args{
				getVpBytes: func() []byte {
					b, _ := (&verifiable.Presentation{}).MarshalJSON()
					return b
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Error ValidateCredentialProof",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return vdr
				},
				getVcVerifier: func() vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(errors.New("some error"))
					return mockVerifier
				},
			},
			args: args{
				getVpBytes: func() []byte {
					b, _ := signedVP.MarshalJSON()
					return b
				},
				validateCredentialProof: true,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Error ValidateVCStatus",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return vdr
				},
				getVcVerifier: func() vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateVCStatus(
						gomock.Any(),
						gomock.Any()).Times(1).Return(errors.New("some error"))
					return mockVerifier
				},
			},
			args: args{
				getVpBytes: func() []byte {
					b, _ := signedVP.MarshalJSON()
					return b
				},
				validateCredentialStatus: true,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vdr:            tt.fields.getVDR(),
				documentLoader: loader,
				vcVerifier:     tt.fields.getVcVerifier(),
			}
			got, err := s.parseAndVerifyPresentation(
				tt.args.getVpBytes(),
				tt.args.validateCredentialProof,
				tt.args.validateCredentialStatus,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAndVerifyPresentation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAndVerifyPresentation() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_validateProofData(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	signedVP, vdr := testutil.SignedVP(
		t, []byte(sampleVPJsonLD), kmskeytypes.ED25519Type, verifiable.SignatureProofValue, loader, crypto.AssertionMethod)
	type fields struct {
		vdr vdrapi.Registry
	}
	type args struct {
		getVP func() *verifiable.Presentation
		opts  *Options
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				vdr: vdr,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					return signedVP
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: crypto.Challenge,
				},
			},
			wantErr: false,
		},
		{
			name: "OK empty options",
			fields: fields{
				vdr: vdr,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVP
					vp.Proofs = make([]verifiable.Proof, 1)
					vp.Proofs[0] = map[string]interface{}{}
					for k, v := range signedVP.Proofs[0] {
						vp.Proofs[0][k] = v
					}
					delete(vp.Proofs[0], crypto.Domain)
					delete(vp.Proofs[0], crypto.Challenge)
					return vp
				},
				opts: nil,
			},
			wantErr: false,
		},
		{
			name: "Error empty proof",
			fields: fields{
				vdr: vdr,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVP
					vp.Proofs = make([]verifiable.Proof, 1)
					vp.Proofs[0] = map[string]interface{}{}
					return vp
				},
				opts: &Options{},
			},
			wantErr: true,
		},
		{
			name: "Error invalid challenge",
			fields: fields{
				vdr: vdr,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					return signedVP
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: "some value",
				},
			},
			wantErr: true,
		},
		{
			name: "Error invalid domain",
			fields: fields{
				vdr: vdr,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					return signedVP
				},
				opts: &Options{
					Domain:    "some value",
					Challenge: crypto.Challenge,
				},
			},
			wantErr: true,
		},
		{
			name: "Error invalid verification method",
			fields: fields{
				vdr: vdr,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVP
					vp.Proofs = make([]verifiable.Proof, 1)
					vp.Proofs[0] = map[string]interface{}{}
					for k, v := range signedVP.Proofs[0] {
						vp.Proofs[0][k] = v
					}
					delete(vp.Proofs[0], crypto.VerificationMethod)
					return vp
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: crypto.Challenge,
				},
			},
			wantErr: true,
		},
		{
			name: "Error invalid verification method",
			fields: fields{
				vdr: vdr,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVP
					vp.Proofs = make([]verifiable.Proof, 1)
					vp.Proofs[0] = map[string]interface{}{}
					for k, v := range signedVP.Proofs[0] {
						vp.Proofs[0][k] = v
					}
					vp.Proofs[0][crypto.VerificationMethod] = "some value"
					return vp
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: crypto.Challenge,
				},
			},
			wantErr: true,
		},
		{
			name: "Error unresolved did doc",
			fields: fields{
				vdr: &mockvdr.MockVDRegistry{},
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					return signedVP
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: crypto.Challenge,
				},
			},
			wantErr: true,
		},
		{
			name: "Error invalid holder",
			fields: fields{
				vdr: vdr,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := *signedVP
					vp.Holder = "invalid holder"
					return &vp
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: crypto.Challenge,
				},
			},
			wantErr: true,
		},
		{
			name: "Error invalid proof purpose",
			fields: fields{
				vdr: vdr,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVP
					vp.Proofs = make([]verifiable.Proof, 1)
					vp.Proofs[0] = map[string]interface{}{}
					for k, v := range signedVP.Proofs[0] {
						vp.Proofs[0][k] = v
					}
					delete(vp.Proofs[0], crypto.Purpose)
					return vp
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: crypto.Challenge,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{vdr: tt.fields.vdr}
			if err := s.validateProofData(tt.args.getVP(), tt.args.opts); (err != nil) != tt.wantErr {
				t.Errorf("validateProofData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
