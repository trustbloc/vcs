/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didconfiguration

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
	"github.com/trustbloc/vcs/pkg/profile"
)

func TestDidConfiguration(t *testing.T) {
	cases := []struct {
		name            string
		profileType     ProfileType
		profileID       string
		verifierProfile *profile.Verifier
		issuerProfile   *profile.Issuer
		expectedFormat  vcsverifiable.Format
		expectedSigner  *vc.Signer
		expectedIssuer  string
	}{
		{
			name:        "Get DID Config for Verifier with ldp",
			profileID:   "verifier_profile",
			profileType: ProfileTypeVerifier,
			verifierProfile: &profile.Verifier{
				SigningDID: &profile.SigningDID{
					DID:     "sign_did",
					Creator: "creator123",
				},
				OIDCConfig: &profile.OIDC4VPConfig{
					ROSigningAlgorithm: vcsverifiable.Ed25519Signature2018,
					KeyType:            kms.ED25519Type,
				},
				Checks: &profile.VerificationChecks{
					Credential: profile.CredentialChecks{
						Format: []vcsverifiable.Format{vcsverifiable.Ldp},
					},
				},
			},
			expectedIssuer: "sign_did",
			expectedFormat: vcsverifiable.Ldp,
			expectedSigner: &vc.Signer{
				DID:           "sign_did",
				Creator:       "creator123",
				SignatureType: vcsverifiable.Ed25519Signature2018,
				KeyType:       kms.ED25519Type,
			},
		},
		{
			name:        "Get DID Config for Issuer with ldp",
			profileID:   "issuer_profile",
			profileType: ProfileTypeIssuer,
			issuerProfile: &profile.Issuer{
				SigningDID: &profile.SigningDID{
					DID:     "sign_did",
					Creator: "creator123",
				},
				VCConfig: &profile.VCConfig{
					Format:                  vcsverifiable.Ldp,
					SigningAlgorithm:        vcsverifiable.Ed25519Signature2018,
					KeyType:                 kms.ED25519Type,
					SignatureRepresentation: verifiable.SignatureJWS,
				},
			},
			expectedIssuer: "sign_did",
			expectedFormat: vcsverifiable.Ldp,
			expectedSigner: &vc.Signer{
				DID:           "sign_did",
				Creator:       "creator123",
				SignatureType: vcsverifiable.Ed25519Signature2018,
				KeyType:       kms.ED25519Type,
			},
		},
		{
			name:        "Get DID Config for Issuer with ldp",
			profileID:   "issuer_profile",
			profileType: ProfileTypeIssuer,
			issuerProfile: &profile.Issuer{
				SigningDID: &profile.SigningDID{
					DID:     "sign_did",
					Creator: "creator123",
				},
				VCConfig: &profile.VCConfig{
					Format:                  vcsverifiable.Jwt,
					SigningAlgorithm:        vcsverifiable.Ed25519Signature2018,
					KeyType:                 kms.ED25519Type,
					SignatureRepresentation: verifiable.SignatureJWS,
				},
			},
			expectedIssuer: "sign_did",
			expectedFormat: vcsverifiable.Jwt,
			expectedSigner: &vc.Signer{
				DID:           "sign_did",
				Creator:       "creator123",
				SignatureType: vcsverifiable.Ed25519Signature2018,
				KeyType:       kms.ED25519Type,
			},
		},
	}

	signedJwt := "signed_jwt"

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
			keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return([]kms.KeyType{
				kms.ED25519Type,
				kms.X25519ECDHKWType,
			})

			kmsRegistrySvc := NewMockKmsRegistry(gomock.NewController(t))
			kmsRegistrySvc.EXPECT().GetKeyManager(gomock.Any()).Return(keyManager, nil)

			verifierProfileSvc := NewMockVerifierProfileService(gomock.NewController(t))
			if testCase.verifierProfile != nil {
				verifierProfileSvc.EXPECT().GetProfile(testCase.profileID).Return(testCase.verifierProfile, nil)
			}

			issuerProfilerSvc := NewMockIssuerProfileService(gomock.NewController(t))
			if testCase.issuerProfile != nil {
				issuerProfilerSvc.EXPECT().GetProfile(testCase.profileID).Return(testCase.issuerProfile, nil)
			}

			cryptoSvc := NewMockVCCrypto(gomock.NewController(t))

			cryptoSvc.EXPECT().SignCredential(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(
					signer *vc.Signer,
					credential *verifiable.Credential,
					issuerSigningOpts ...crypto.SigningOpts,
				) (*verifiable.Credential, error) {
					assert.Equal(t, testCase.expectedSigner.DID, signer.DID)
					assert.Equal(t, testCase.expectedSigner.Creator, signer.Creator)
					assert.Equal(t, testCase.expectedSigner.SignatureType, signer.SignatureType)
					assert.Equal(t, testCase.expectedSigner.KeyType, signer.KeyType)
					assert.NotNil(t, signer.KMS)

					assert.Equal(t, []string{
						"https://www.w3.org/2018/credentials/v1",
						"https://identity.foundation/.well-known/did-configuration/v1",
					}, credential.Context)

					assert.Equal(t, []string{
						"VerifiableCredential",
						"DomainLinkageCredential",
					}, credential.Types)

					assert.Equal(t, testCase.expectedIssuer, credential.Issuer.ID)

					credential.JWT = signedJwt
					credential.Proofs = []verifiable.Proof{{}}

					return credential, nil
				})

			didConfigurationService := New(&Config{
				VerifierProfileService: verifierProfileSvc,
				IssuerProfileService:   issuerProfilerSvc,
				Crypto:                 cryptoSvc,
				KmsRegistry:            kmsRegistrySvc,
			})

			resp, err := didConfigurationService.DidConfig(context.TODO(),
				testCase.profileType, testCase.profileID)

			assert.Nil(t, err)

			assert.Equal(t, didConfigurationContextURL, resp.Context)

			switch testCase.expectedFormat {
			case vcsverifiable.Ldp:
				cred, ok := resp.LinkedDiDs[0].(*verifiable.Credential)

				if !ok {
					t.Fatal(errors.New("can not map to *verifiable.Credential"))
				}

				assert.Len(t, cred.Proofs, 1)
				assert.Equal(t, testCase.expectedIssuer, cred.Issuer.ID)
			case vcsverifiable.Jwt:
				jws, ok := resp.LinkedDiDs[0].(string)

				if !ok {
					t.Fatal(errors.New("can not map to string"))
				}

				assert.Equal(t, signedJwt, jws)
			}
		})
	}
}

func TestDidConfigWithInvalidArgs(t *testing.T) {
	cases := []struct {
		name        string
		profileType ProfileType
		errorText   string
	}{
		{
			name:        "invalid profile type",
			profileType: "random_profile_type",
			errorText:   "profileType should be verifier or issuer",
		},
		{
			name:        "issuer profile not found",
			profileType: ProfileTypeIssuer,
			errorText:   "not found",
		},
		{
			name:        "verifier profile not found",
			profileType: ProfileTypeVerifier,
			errorText:   "not found",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			verifierProfileSvc := NewMockVerifierProfileService(gomock.NewController(t))
			issuerProfileSvc := NewMockIssuerProfileService(gomock.NewController(t))

			switch testCase.profileType {
			case ProfileTypeVerifier:
				verifierProfileSvc.EXPECT().GetProfile(gomock.Any()).Return(nil, errors.New("not found"))
			case ProfileTypeIssuer:
				issuerProfileSvc.EXPECT().GetProfile(gomock.Any()).Return(nil, errors.New("not found"))
			}

			configService := New(&Config{
				VerifierProfileService: verifierProfileSvc,
				IssuerProfileService:   issuerProfileSvc,
			})

			resp, err := configService.DidConfig(context.TODO(),
				testCase.profileType,
				"123",
			)

			assert.Nil(t, resp)
			assert.ErrorContains(t, err, testCase.errorText)
		})
	}
}

func TestValidateOIDCConfigForVerifier(t *testing.T) {
	verifierProfileSvc := NewMockVerifierProfileService(gomock.NewController(t))
	verifierProfileSvc.EXPECT().GetProfile(gomock.Any()).Return(&profile.Verifier{}, nil)

	configService := New(&Config{
		VerifierProfileService: verifierProfileSvc,
	})

	resp, err := configService.DidConfig(context.TODO(),
		ProfileTypeVerifier,
		"123",
	)

	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "oidc config is required for verifier")
}

func TestKmsError(t *testing.T) {
	cases := []struct {
		name        string
		profileType ProfileType
	}{
		{
			name:        "can not request kms for issuer",
			profileType: ProfileTypeIssuer,
		},
		{
			name:        "can not request kms for verifier",
			profileType: ProfileTypeVerifier,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			verifierProfileSvc := NewMockVerifierProfileService(gomock.NewController(t))
			issuerProfileSvc := NewMockIssuerProfileService(gomock.NewController(t))

			if testCase.profileType == ProfileTypeVerifier {
				verifierProfileSvc.EXPECT().GetProfile(gomock.Any()).Return(&profile.Verifier{
					SigningDID: &profile.SigningDID{},
					OIDCConfig: &profile.OIDC4VPConfig{},
					Checks:     &profile.VerificationChecks{},
				}, nil)
			} else {
				issuerProfileSvc.EXPECT().GetProfile(gomock.Any()).Return(&profile.Issuer{
					SigningDID: &profile.SigningDID{},
					VCConfig:   &profile.VCConfig{},
				}, nil)
			}

			kmsRegistrySvc := NewMockKmsRegistry(gomock.NewController(t))
			kmsRegistrySvc.EXPECT().GetKeyManager(gomock.Any()).Return(nil, errors.New("kms error"))

			configService := New(&Config{
				VerifierProfileService: verifierProfileSvc,
				IssuerProfileService:   issuerProfileSvc,
				KmsRegistry:            kmsRegistrySvc,
			})

			conf, err := configService.DidConfig(
				context.TODO(),
				testCase.profileType,
				"123",
			)

			assert.Nil(t, conf)
			assert.ErrorContains(t, err, "kms error")
		})
	}
}

func TestWithSignError(t *testing.T) {
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))
	keyManager.EXPECT().SupportedKeyTypes().AnyTimes().Return([]kms.KeyType{
		kms.ED25519Type,
		kms.X25519ECDHKWType,
	})

	kmsRegistrySvc := NewMockKmsRegistry(gomock.NewController(t))
	kmsRegistrySvc.EXPECT().GetKeyManager(gomock.Any()).Return(keyManager, nil)

	verifierProfileSvc := NewMockVerifierProfileService(gomock.NewController(t))

	verifierProfileSvc.EXPECT().GetProfile(gomock.Any()).Return(&profile.Verifier{
		SigningDID: &profile.SigningDID{},
		OIDCConfig: &profile.OIDC4VPConfig{},
		Checks:     &profile.VerificationChecks{},
	}, nil)

	cryptoSvc := NewMockVCCrypto(gomock.NewController(t))

	cryptoSvc.EXPECT().SignCredential(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		nil, errors.New("sign error"))

	configService := New(&Config{
		VerifierProfileService: verifierProfileSvc,
		KmsRegistry:            kmsRegistrySvc,
		Crypto:                 cryptoSvc,
	})

	cred, err := configService.DidConfig(
		context.TODO(),
		ProfileTypeVerifier,
		"123",
	)

	assert.Nil(t, cred)
	assert.ErrorContains(t, err, "sign error")
}
