/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifypresentation

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	timeutil "github.com/trustbloc/did-go/doc/util/time"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	mockvdr "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/vc-go/sdjwt/common"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

var (
	//go:embed testdata/requested_credentials_vp.jsonld
	requestedCredentialsVP []byte
	//go:embed testdata/client_attestation_vp.jsonld
	clientAttestationVP []byte
)

const (
	verifierDID = "did:key:abc"
)

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)

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
					VDR:                      &mockvdr.VDRegistry{},
					DocumentLoader:           testutil.DocumentLoader(t),
					VcVerifier:               NewMockVcVerifier(ctrl),
					ClientAttestationService: NewMockClientAttestationService(ctrl),
				},
			},
			want: &Service{
				vdr:                      &mockvdr.VDRegistry{},
				documentLoader:           testutil.DocumentLoader(t),
				vcVerifier:               NewMockVcVerifier(ctrl),
				clientAttestationService: NewMockClientAttestationService(ctrl),
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
	signedClientAttestationVP := testutil.SignedVP(t, clientAttestationVP, vcs.Ldp)
	signedRequestedCredentialsVP := testutil.SignedVP(t, requestedCredentialsVP, vcs.Ldp)

	type fields struct {
		getVDR                  func() vdrapi.Registry
		getVcVerifier           func(t *testing.T) vcVerifier
		getClientAttestationSrv func(t *testing.T) clientAttestationService
	}
	type args struct {
		getPresentation func(t *testing.T) *verifiable.Presentation
		profile         *profileapi.Verifier
		opts            *Options
	}
	tests := []struct {
		name    string
		marshal bool
		fields  fields
		args    args
		want    []PresentationVerificationCheckResult
		wantErr bool
	}{
		{
			name: "OK with Trust registry validation enabled and client attestation VC included in VP",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return signedClientAttestationVP.VDR
				},
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(nil)
					mockVerifier.EXPECT().ValidateVCStatus(
						context.Background(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(nil)
					mockVerifier.EXPECT().ValidateLinkedDomain(
						context.Background(),
						gomock.Any()).Times(1).Return(nil)
					return mockVerifier
				},
				getClientAttestationSrv: func(t *testing.T) clientAttestationService {
					tr := NewMockClientAttestationService(gomock.NewController(t))

					tr.EXPECT().ValidateAttestationJWTVP(
						context.Background(),
						gomock.Any(),
						"https://trustregistry.example.com",
						verifierDID,
						gomock.Any(),
					).Return(nil)

					return tr
				},
			},
			args: args{
				getPresentation: func(t *testing.T) *verifiable.Presentation {
					return signedClientAttestationVP.Presentation
				},
				profile: &profileapi.Verifier{
					Policy:     profileapi.Policy{URL: "https://trustregistry.example.com"},
					SigningDID: &profileapi.SigningDID{DID: verifierDID},
					Checks: &profileapi.VerificationChecks{
						Presentation: &profileapi.PresentationChecks{
							Proof:  true,
							Format: nil,
						},
						Credential: profileapi.CredentialChecks{
							Proof:            true,
							Status:           true,
							LinkedDomain:     true,
							Format:           nil,
							CredentialExpiry: true,
							Strict:           true,
							IssuerTrustList: map[string]profileapi.TrustList{
								"https://example.edu/issuers/14": {},
							},
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
			name: "OK with Trust registry validation disabled and client attestation VC included in VP",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return signedClientAttestationVP.VDR
				},
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(2).Return(nil)
					mockVerifier.EXPECT().ValidateVCStatus(
						context.Background(),
						gomock.Any(),
						gomock.Any()).Times(2).Return(nil)
					mockVerifier.EXPECT().ValidateLinkedDomain(
						context.Background(),
						gomock.Any()).Times(1).Return(nil)
					return mockVerifier
				},
				getClientAttestationSrv: func(t *testing.T) clientAttestationService {
					return NewMockClientAttestationService(gomock.NewController(t))
				},
			},
			args: args{
				getPresentation: func(t *testing.T) *verifiable.Presentation {
					return signedClientAttestationVP.Presentation
				},
				profile: &profileapi.Verifier{
					SigningDID: &profileapi.SigningDID{DID: verifierDID},
					Checks: &profileapi.VerificationChecks{
						Presentation: &profileapi.PresentationChecks{
							Proof:  true,
							Format: nil,
						},
						Credential: profileapi.CredentialChecks{
							Proof:            true,
							Status:           true,
							LinkedDomain:     true,
							Format:           nil,
							CredentialExpiry: true,
							Strict:           true,
							IssuerTrustList: map[string]profileapi.TrustList{
								"https://example.edu/issuers/14": {},
							},
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
			name: "Err credential type not in trust list",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return signedRequestedCredentialsVP.VDR
				},
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(nil)
					mockVerifier.EXPECT().ValidateVCStatus(
						context.Background(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(nil)
					mockVerifier.EXPECT().ValidateLinkedDomain(
						context.Background(),
						gomock.Any()).Times(1).Return(nil)
					return mockVerifier
				},
				getClientAttestationSrv: func(t *testing.T) clientAttestationService {
					return nil
				},
			},
			args: args{
				getPresentation: func(t *testing.T) *verifiable.Presentation {
					return signedRequestedCredentialsVP.Presentation
				},
				profile: &profileapi.Verifier{
					SigningDID: &profileapi.SigningDID{DID: verifierDID},
					Checks: &profileapi.VerificationChecks{
						Presentation: &profileapi.PresentationChecks{
							Proof:  true,
							Format: nil,
						},
						Credential: profileapi.CredentialChecks{
							Proof:            true,
							Status:           true,
							LinkedDomain:     true,
							Format:           nil,
							CredentialExpiry: true,
							Strict:           true,
							IssuerTrustList: map[string]profileapi.TrustList{
								"https://example.edu/issuers/14": {
									CredentialTypes: []string{
										"DrivingLicense",
									},
								},
							},
						},
					},
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: crypto.Challenge,
				},
			},
			want: []PresentationVerificationCheckResult{
				{
					Check: "issuerTrustList",
					Error: "credential type: UniversityDegreeCredential is not a member of trustlist configuration",
				},
			},
			wantErr: false,
		},
		{
			name: "OK no checks",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return nil
				},
				getVcVerifier: func(t *testing.T) vcVerifier {
					return nil
				},
				getClientAttestationSrv: func(t *testing.T) clientAttestationService {
					return nil
				},
			},
			args: args{
				getPresentation: func(t *testing.T) *verifiable.Presentation {
					return nil
				},
				profile: &profileapi.Verifier{
					Checks: &profileapi.VerificationChecks{
						Presentation: &profileapi.PresentationChecks{
							Proof:  false,
							Format: nil,
						},
						Credential: profileapi.CredentialChecks{
							Proof:  false,
							Status: false,
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
			name: "Error all checks",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return signedClientAttestationVP.VDR
				},
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(errors.New("some error"))
					mockVerifier.EXPECT().ValidateVCStatus(
						context.Background(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(errors.New("some error"))
					mockVerifier.EXPECT().ValidateLinkedDomain(
						context.Background(),
						gomock.Any()).Times(1).Return(errors.New("some error"))
					return mockVerifier
				},
				getClientAttestationSrv: func(t *testing.T) clientAttestationService {
					ca := NewMockClientAttestationService(gomock.NewController(t))

					ca.EXPECT().ValidateAttestationJWTVP(
						context.Background(),
						gomock.Any(),
						"https://trustregistry.example.com",
						verifierDID,
						gomock.Any(),
					).Return(errors.New("some error"))

					return ca
				},
			},
			args: args{
				getPresentation: func(t *testing.T) *verifiable.Presentation {
					return signedClientAttestationVP.Presentation
				},
				profile: &profileapi.Verifier{
					Policy:     profileapi.Policy{URL: "https://trustregistry.example.com"},
					SigningDID: &profileapi.SigningDID{DID: verifierDID},
					Checks: &profileapi.VerificationChecks{
						Presentation: &profileapi.PresentationChecks{
							Proof:  false,
							Format: nil,
						},
						Credential: profileapi.CredentialChecks{
							Proof:        true,
							Status:       true,
							LinkedDomain: true,
							Format:       nil,
							IssuerTrustList: map[string]profileapi.TrustList{
								"random": {},
							},
						},
					},
				},
				opts: &Options{
					Domain:    crypto.Domain,
					Challenge: crypto.Challenge,
				},
			},
			want: []PresentationVerificationCheckResult{
				{
					Check: "clientAttestation",
					Error: "some error",
				},
				{
					Check: "issuerTrustList",
					Error: "issuer with id: https://example.edu/issuers/14 is not a member of trustlist",
				},
				{
					Check: "credentialProof",
					Error: "some error",
				},
				{
					Check: "credentialStatus",
					Error: "some error",
				},
				{
					Check: "linkedDomain",
					Error: "some error",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vdr:                      tt.fields.getVDR(),
				documentLoader:           loader,
				vcVerifier:               tt.fields.getVcVerifier(t),
				clientAttestationService: tt.fields.getClientAttestationSrv(t),
			}

			got, _, err := s.VerifyPresentation(context.Background(), tt.args.getPresentation(t), tt.args.opts, tt.args.profile)
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

func TestService_validatePresentationProof(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	signedVPResult := testutil.SignedVP(t, requestedCredentialsVP, vcs.Ldp)

	type fields struct {
		getVDR func() vdrapi.Registry
	}
	type args struct {
		getVpBytes func() []byte
		getOpts    func() *Options
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
				getVDR: func() vdrapi.Registry {
					return signedVPResult.VDR
				},
			},
			args: args{
				getVpBytes: func() []byte {
					b, _ := signedVPResult.Presentation.MarshalJSON()
					return b
				},
				getOpts: func() *Options {
					return &Options{
						Domain:    crypto.Domain,
						Challenge: crypto.Challenge,
					}
				},
			},
			wantErr: false,
		},
		{
			name: "Error empty VDR",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &mockvdr.VDRegistry{}
				},
			},
			args: args{
				getVpBytes: func() []byte {
					b, _ := signedVPResult.Presentation.MarshalJSON()
					return b
				},
				getOpts: func() *Options {
					return &Options{}
				},
			},
			wantErr: true,
		},
		{
			name: "Error invalid Presentation",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return signedVPResult.VDR
				},
			},
			args: args{
				getVpBytes: func() []byte {
					b, _ := (&verifiable.Presentation{}).MarshalJSON()
					return b
				},
				getOpts: func() *Options {
					return &Options{}
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vdr:            tt.fields.getVDR(),
				documentLoader: loader,
			}
			err := s.validatePresentationProof(
				tt.args.getVpBytes(),
				tt.args.getOpts(),
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAndVerifyPresentation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestService_validateProofData(t *testing.T) {
	signedVPResult := testutil.SignedVP(t, requestedCredentialsVP, vcs.Ldp)
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
				vdr: signedVPResult.VDR,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					return signedVPResult.Presentation
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
				vdr: signedVPResult.VDR,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVPResult.Presentation
					vp.Proofs = make([]verifiable.Proof, 1)
					vp.Proofs[0] = map[string]interface{}{}
					for k, v := range signedVPResult.Presentation.Proofs[0] {
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
				vdr: signedVPResult.VDR,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVPResult.Presentation
					vp.Proofs = make([]verifiable.Proof, 0)
					return vp
				},
				opts: &Options{},
			},
			wantErr: true,
		},
		{
			name: "Error invalid challenge",
			fields: fields{
				vdr: signedVPResult.VDR,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					return signedVPResult.Presentation
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
				vdr: signedVPResult.VDR,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					return signedVPResult.Presentation
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
				vdr: signedVPResult.VDR,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVPResult.Presentation
					vp.Proofs = make([]verifiable.Proof, 1)
					vp.Proofs[0] = map[string]interface{}{}
					for k, v := range signedVPResult.Presentation.Proofs[0] {
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
				vdr: signedVPResult.VDR,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVPResult.Presentation
					vp.Proofs = make([]verifiable.Proof, 1)
					vp.Proofs[0] = map[string]interface{}{}
					for k, v := range signedVPResult.Presentation.Proofs[0] {
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
				vdr: &mockvdr.VDRegistry{},
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					return signedVPResult.Presentation
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
				vdr: signedVPResult.VDR,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := *signedVPResult.Presentation
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
				vdr: signedVPResult.VDR,
			},
			args: args{
				getVP: func() *verifiable.Presentation {
					vp := &verifiable.Presentation{}
					*vp = *signedVPResult.Presentation
					vp.Proofs = make([]verifiable.Proof, 1)
					vp.Proofs[0] = map[string]interface{}{}
					for k, v := range signedVPResult.Presentation.Proofs[0] {
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

func TestService_validateCredentialsProof(t *testing.T) {
	type fields struct {
		getVcVerifier func(t *testing.T) vcVerifier
	}
	type args struct {
		trustRegistryValidationEnabled bool
		getCredentials                 func(t *testing.T) []*verifiable.Credential
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "OK with trustRegistryValidationEnabled == true and Wallet Attestation VC included",
			fields: fields{
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(nil)
					return mockVerifier
				},
			},
			args: args{
				trustRegistryValidationEnabled: true,
				getCredentials: func(t *testing.T) []*verifiable.Credential {
					credContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"UniversityDegreeCredential",
						},
					}

					credential, err := verifiable.CreateCredential(credContent, nil)
					assert.NoError(t, err)

					attestationVCContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"WalletAttestationCredential",
						},
					}

					attestationVC, err := verifiable.CreateCredential(attestationVCContent, nil)
					assert.NoError(t, err)

					return []*verifiable.Credential{credential, attestationVC}
				},
			},
			wantErr: false,
		},
		{
			name: "OK with trustRegistryValidationEnabled == false and Wallet Attestation VC included",
			fields: fields{
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(2).Return(nil)
					return mockVerifier
				},
			},
			args: args{
				trustRegistryValidationEnabled: false,
				getCredentials: func(t *testing.T) []*verifiable.Credential {
					credContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"UniversityDegreeCredential",
						},
					}

					credential, err := verifiable.CreateCredential(credContent, nil)
					assert.NoError(t, err)

					attestationVCContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"WalletAttestationCredential",
						},
					}

					attestationVC, err := verifiable.CreateCredential(attestationVCContent, nil)
					assert.NoError(t, err)

					return []*verifiable.Credential{credential, attestationVC}
				},
			},
			wantErr: false,
		},
		{
			name: "Error",
			fields: fields{
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateCredentialProof(
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any(),
						gomock.Any()).Times(1).Return(errors.New("some error"))
					return mockVerifier
				},
			},
			args: args{
				trustRegistryValidationEnabled: false,
				getCredentials: func(t *testing.T) []*verifiable.Credential {
					credContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"UniversityDegreeCredential",
						},
					}

					credential, err := verifiable.CreateCredential(credContent, nil)
					assert.NoError(t, err)

					return []*verifiable.Credential{credential}
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vcVerifier: tt.fields.getVcVerifier(t),
			}

			if err := s.validateCredentialsProof(
				context.Background(),
				"",
				tt.args.getCredentials(t),
				tt.args.trustRegistryValidationEnabled,
			); (err != nil) != tt.wantErr {
				t.Errorf("validateCredentialsProof() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_validateCredentialsStatus(t *testing.T) {
	type fields struct {
		getVcVerifier func(t *testing.T) vcVerifier
	}
	type args struct {
		getCredentials                 func(t *testing.T) []*verifiable.Credential
		trustRegistryValidationEnabled bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "OK with trustRegistryValidationEnabled == true and Wallet Attestation VC",
			fields: fields{
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateVCStatus(
						context.Background(),
						&verifiable.TypedID{ID: "TypedID"},
						&verifiable.Issuer{ID: "IssuerID"},
					).Times(1).Return(nil)
					return mockVerifier
				},
			},
			args: args{
				trustRegistryValidationEnabled: true,
				getCredentials: func(t *testing.T) []*verifiable.Credential {
					credContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"UniversityDegreeCredential",
						},
						Status: &verifiable.TypedID{ID: "TypedID"},
						Issuer: &verifiable.Issuer{ID: "IssuerID"},
					}

					cred1, err := verifiable.CreateCredential(credContent, nil)
					assert.NoError(t, err)

					attestationVCContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"WalletAttestationCredential",
						},
						Status: &verifiable.TypedID{ID: "TypedID"},
						Issuer: &verifiable.Issuer{ID: "IssuerID"},
					}

					attestationVC, err := verifiable.CreateCredential(attestationVCContent, nil)
					assert.NoError(t, err)

					return []*verifiable.Credential{cred1, attestationVC}
				},
			},
			wantErr: false,
		},
		{
			name: "OK with trustRegistryValidationEnabled == false and Wallet Attestation VC",
			fields: fields{
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateVCStatus(
						context.Background(),
						&verifiable.TypedID{ID: "TypedID"},
						&verifiable.Issuer{ID: "IssuerID"},
					).Times(1).Return(nil)
					return mockVerifier
				},
			},
			args: args{
				trustRegistryValidationEnabled: false,
				getCredentials: func(t *testing.T) []*verifiable.Credential {
					attestationVCContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"WalletAttestationCredential",
						},
						Status: &verifiable.TypedID{ID: "TypedID"},
						Issuer: &verifiable.Issuer{ID: "IssuerID"},
					}

					attestationVC, err := verifiable.CreateCredential(attestationVCContent, nil)
					assert.NoError(t, err)

					return []*verifiable.Credential{attestationVC}
				},
			},
			wantErr: false,
		},
		{
			name: "OK with empty typedID",
			fields: fields{
				getVcVerifier: func(t *testing.T) vcVerifier {
					return NewMockVcVerifier(gomock.NewController(t))
				},
			},
			args: args{
				trustRegistryValidationEnabled: false,
				getCredentials: func(t *testing.T) []*verifiable.Credential {
					credContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"UniversityDegreeCredential",
						},
						Issuer: &verifiable.Issuer{ID: "IssuerID"},
					}

					cred1, err := verifiable.CreateCredential(credContent, nil)
					assert.NoError(t, err)

					return []*verifiable.Credential{cred1}
				},
			},
			wantErr: false,
		},
		{
			name: "Error ValidateVCStatus",
			fields: fields{
				getVcVerifier: func(t *testing.T) vcVerifier {
					mockVerifier := NewMockVcVerifier(gomock.NewController(t))
					mockVerifier.EXPECT().ValidateVCStatus(
						context.Background(),
						&verifiable.TypedID{ID: "TypedID"},
						&verifiable.Issuer{ID: "IssuerID"},
					).Times(1).Return(errors.New("some error"))
					return mockVerifier
				},
			},
			args: args{
				getCredentials: func(t *testing.T) []*verifiable.Credential {
					credContent := verifiable.CredentialContents{
						Types: []string{
							"VerifiableCredential",
							"UniversityDegreeCredential",
						},
						Status: &verifiable.TypedID{ID: "TypedID"},
						Issuer: &verifiable.Issuer{ID: "IssuerID"},
					}

					cred1, err := verifiable.CreateCredential(credContent, nil)
					assert.NoError(t, err)

					return []*verifiable.Credential{cred1}
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vcVerifier: tt.fields.getVcVerifier(t),
			}
			if err := s.validateCredentialsStatus(
				context.Background(),
				tt.args.getCredentials(t),
				tt.args.trustRegistryValidationEnabled); (err != nil) != tt.wantErr {
				t.Errorf("validateCredentialsStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractCredentialStatus(t *testing.T) {
	s := &Service{}

	t.Run("nil", func(t *testing.T) {
		v, issuer := s.extractCredentialStatus(nil)
		assert.Nil(t, v)
		assert.Empty(t, issuer)
	})
}

func TestCredentialStrict(t *testing.T) {
	l, err := verifiable.CreateCredential(verifiable.CredentialContents{
		ID: "credentialID",
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		Types: []string{
			"VerifiableCredential",
		},
		Subject: []verifiable.Subject{
			{
				CustomFields: map[string]interface{}{
					"type":   []interface{}{"VerifiedEmployee"},
					"degree": "abcd",
				},
			},
		},
	}, nil)
	assert.NoError(t, err)

	l.JWTEnvelope = &verifiable.JWTEnvelope{
		SDJWTDisclosures: []*common.DisclosureClaim{
			{
				Name:  "_sd",
				Value: "aaaaaa",
			},
			{
				Name:  "degreeType",
				Value: "random",
			},
		}}

	s := New(&Config{
		DocumentLoader: testutil.DocumentLoader(t),
	})
	claimKeys, err := s.checkCredentialStrict(context.TODO(), []*verifiable.Credential{l})
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"type", "degree"}, claimKeys["credentialID"])
}

func TestCheckTrustList(t *testing.T) {
	s := New(&Config{})

	t.Run("Success - attestation credential with invalid issuer ignored", func(t *testing.T) {
		credContent := verifiable.CredentialContents{
			Types: []string{
				"VerifiableCredential",
				"UniversityDegreeCredential",
			},
			Issuer: &verifiable.Issuer{
				ID: "a",
			}}

		attestationVCContent := verifiable.CredentialContents{
			Types: []string{
				"VerifiableCredential",
				"WalletAttestationCredential",
			},
			Issuer: &verifiable.Issuer{
				ID: "123432123",
			}}

		cred1, err := verifiable.CreateCredential(credContent, nil)
		assert.NoError(t, err)

		attestationVC, err := verifiable.CreateCredential(attestationVCContent, nil)
		assert.NoError(t, err)

		err = s.checkIssuerTrustList(
			context.TODO(),
			[]*verifiable.Credential{cred1, attestationVC},
			map[string]profileapi.TrustList{
				"a": {},
			},
		)

		assert.ErrorContains(t, err, "issuer with id: 123432123 is not a member of trustlist")
	})

	t.Run("from credentials v1 trust list", func(t *testing.T) {
		credContent := verifiable.CredentialContents{
			Types: []string{
				"VerifiableCredential",
				"UniversityDegreeCredential",
			},
			Issuer: &verifiable.Issuer{
				ID: "123432123",
			}}

		cred, err := verifiable.CreateCredential(credContent, nil)
		assert.NoError(t, err)

		err = s.checkIssuerTrustList(
			context.TODO(),
			[]*verifiable.Credential{cred},
			map[string]profileapi.TrustList{
				"a": {},
			},
		)

		assert.ErrorContains(t, err, "issuer with id: 123432123 is not a member of trustlist")
	})
}

func TestService_checkCredentialExpiry(t *testing.T) {
	tests := []struct {
		name                           string
		getCredentials                 func() []*verifiable.Credential
		wantErr                        assert.ErrorAssertionFunc
		trustRegistryValidationEnabled bool
	}{
		{
			name: "Success with trustRegistryValidationEnabled == true and expired Wallet Attestation VC",
			getCredentials: func() []*verifiable.Credential {
				credContent := verifiable.CredentialContents{
					Types: []string{
						"VerifiableCredential",
						"UniversityDegreeCredential",
					},
					Expired: timeutil.NewTime(time.Now().Add(time.Hour)),
				}

				attestationVCContent := verifiable.CredentialContents{
					Types: []string{
						"VerifiableCredential",
						"WalletAttestationCredential",
					},
					Expired: timeutil.NewTime(time.Now().Add(-time.Hour)),
				}

				cred1, err := verifiable.CreateCredential(credContent, nil)
				assert.NoError(t, err)

				attestationVC, err := verifiable.CreateCredential(attestationVCContent, nil)
				assert.NoError(t, err)

				return []*verifiable.Credential{cred1, attestationVC}
			},
			trustRegistryValidationEnabled: true,
			wantErr:                        assert.NoError,
		},
		{
			name: "Error with expired VC",
			getCredentials: func() []*verifiable.Credential {
				credContent := verifiable.CredentialContents{
					Types: []string{
						"VerifiableCredential",
						"UniversityDegreeCredential",
					},
					Expired: timeutil.NewTime(time.Now().Add(-time.Hour)),
				}

				cred1, err := verifiable.CreateCredential(credContent, nil)
				assert.NoError(t, err)

				return []*verifiable.Credential{cred1}
			},
			trustRegistryValidationEnabled: true,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "credential expired")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			credentials := tt.getCredentials()
			tt.wantErr(t,
				(&Service{}).checkCredentialExpiry(ctx, credentials, tt.trustRegistryValidationEnabled),
				fmt.Sprintf("checkCredentialExpiry(%v, %v)", ctx, credentials),
			)
		})
	}
}
