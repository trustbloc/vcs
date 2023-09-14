/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	_ "embed"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

//go:embed testdata/profile.json
var profileJSON []byte //nolint:gochecknoglobals

func TestController_GetOpenIDCredentialIssuerConfig(t *testing.T) {
	var (
		externalHostURL       = "https://example.com/"
		mockTestIssuerProfile *profileapi.Issuer
		mockKMSRegistry       = NewMockKMSRegistry(gomock.NewController(t))
		mockCryptoJWTSigner   = NewMockCryptoJWTSigner(gomock.NewController(t))
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration, jwt string, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTestIssuerProfile = loadProfile(t)

				mockKMSRegistry.EXPECT().GetKeyManager(&vcskms.Config{
					KMSType:  "local",
					Endpoint: "https://example.com",
				}).Return(nil, nil)

				mockCryptoJWTSigner.EXPECT().NewJWTSigned(gomock.Any(), &vc.Signer{
					Creator:  "did:orb:bank_issuer#123",
					KMSKeyID: "123",
					KeyType:  "ECDSASecp256k1DER",
				}).Return("aa.bb.cc", nil)
			},
			check: func(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration, jwt string, err error) {
				checkWithSuffix(t, res)

				assert.Equal(t, "aa.bb.cc", jwt)
				assert.Nil(t, err)
			},
		},
		{
			name: "Success signed issuer metadata is not supported",
			setup: func() {
				mockTestIssuerProfile = loadProfile(t)
				mockTestIssuerProfile.OIDCConfig = nil

				mockKMSRegistry = NewMockKMSRegistry(gomock.NewController(t))
				mockCryptoJWTSigner = NewMockCryptoJWTSigner(gomock.NewController(t))
			},
			check: func(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration, jwt string, err error) {
				checkWithSuffix(t, res)

				assert.Empty(t, "", jwt)
				assert.Nil(t, err)
			},
		},
		{
			name: "Error kmsRegistry",
			setup: func() {
				mockTestIssuerProfile = loadProfile(t)

				mockKMSRegistry.EXPECT().GetKeyManager(&vcskms.Config{
					KMSType:  "local",
					Endpoint: "https://example.com",
				}).Return(nil, errors.New("some error"))

				mockCryptoJWTSigner = NewMockCryptoJWTSigner(gomock.NewController(t))
			},
			check: func(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration, jwt string, err error) {
				assert.Nil(t, res)
				assert.Empty(t, jwt)
				assert.ErrorContains(t, err, "get kms:")
			},
		},
		{
			name: "Error cryptoJWTSigner",
			setup: func() {
				mockTestIssuerProfile = loadProfile(t)

				mockKMSRegistry.EXPECT().GetKeyManager(&vcskms.Config{
					KMSType:  "local",
					Endpoint: "https://example.com",
				}).Return(nil, nil)

				mockCryptoJWTSigner.EXPECT().NewJWTSigned(gomock.Any(), &vc.Signer{
					Creator:  "did:orb:bank_issuer#123",
					KMSKeyID: "123",
					KeyType:  "ECDSASecp256k1DER",
				}).Return("", errors.New("some error"))
			},
			check: func(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration, jwt string, err error) {
				assert.Nil(t, res)
				assert.Empty(t, jwt)
				assert.ErrorContains(t, err, "sign issuer metadata:")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			s := NewService(&Config{
				ExternalHostURL: externalHostURL,
				KMSRegistry:     mockKMSRegistry,
				CryptoJWTSigner: mockCryptoJWTSigner,
			})

			res, jwt, err := s.GetOpenIDCredentialIssuerConfig(mockTestIssuerProfile)

			tt.check(t, res, jwt, err)
		})
	}
}

func TestService_getOpenIDIssuerConfig(t *testing.T) {
	type fields struct {
		externalHostURL string
	}
	type args struct {
		getIssuerProfile func(t *testing.T) *profileapi.Issuer
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		check  func(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration)
	}{
		{
			name: "Success with suffix /",
			fields: fields{
				externalHostURL: "https://example.com/",
			},
			args: args{
				getIssuerProfile: loadProfile,
			},
			check: checkWithSuffix,
		},
		{
			name: "Success without suffix /",
			fields: fields{
				externalHostURL: "https://example.com",
			},
			args: args{
				getIssuerProfile: loadProfile,
			},
			check: checkWithSuffix,
		},
		{
			name: "Success empty issuerProfile.CredentialMetaData.Display",
			fields: fields{
				externalHostURL: "https://example.com",
			},
			args: args{
				getIssuerProfile: func(t *testing.T) *profileapi.Issuer {
					profile := loadProfile(t)
					profile.CredentialMetaData.Display = nil

					return profile
				},
			},
			check: func(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration) {
				t.Helper()

				assert.Equal(t, "https://example.com/oidc/authorize", res.AuthorizationServer)
				assert.Nil(t, res.BatchCredentialEndpoint)
				assert.Equal(t, "https://example.com/oidc/credential", res.CredentialEndpoint)
				assert.Equal(t, "https://example.com/issuer/profileID/profileVersion", res.CredentialIssuer)

				assert.Len(t, res.CredentialsSupported, 1)
				resMapped := (res.CredentialsSupported)[0].(map[string]interface{}) //nolint
				assert.Equal(t, "VerifiedEmployee_JWT", resMapped["id"])
				assert.Equal(t, []string{"orb"}, resMapped["cryptographic_binding_methods_supported"])
				assert.Equal(t, []string{"ECDSASecp256k1DER"}, resMapped["cryptographic_suites_supported"])

				assert.Nil(t, (*res.Display)[0].BackgroundColor)
				assert.Nil(t, (*res.Display)[0].Logo)
				assert.Nil(t, (*res.Display)[0].TextColor)
				assert.Empty(t, (*res.Display)[0].Url)
				assert.Equal(t, "en-US", *(*res.Display)[0].Locale)
				assert.Equal(t, "random_name", *(*res.Display)[0].Name)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				externalHostURL: tt.fields.externalHostURL,
			}

			tt.check(t, s.getOpenIDIssuerConfig(tt.args.getIssuerProfile(t)))
		})
	}
}

func loadProfile(t *testing.T) *profileapi.Issuer {
	t.Helper()

	var profile *profileapi.Issuer
	assert.NoError(t, json.Unmarshal(profileJSON, &profile))

	return profile
}

func checkWithSuffix(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration) {
	t.Helper()

	assert.Equal(t, "https://example.com/oidc/authorize", res.AuthorizationServer)
	assert.Nil(t, res.BatchCredentialEndpoint)
	assert.Equal(t, "https://example.com/oidc/credential", res.CredentialEndpoint)
	assert.Equal(t, "https://example.com/issuer/profileID/profileVersion", res.CredentialIssuer)

	assert.Len(t, res.CredentialsSupported, 1)
	resMapped := (res.CredentialsSupported)[0].(map[string]interface{}) //nolint
	assert.Equal(t, "VerifiedEmployee_JWT", resMapped["id"])
	assert.Equal(t, []string{"orb"}, resMapped["cryptographic_binding_methods_supported"])
	assert.Equal(t, []string{"ECDSASecp256k1DER"}, resMapped["cryptographic_suites_supported"])

	assert.Equal(t, "#FFFFFF", *(*res.Display)[0].BackgroundColor)
	assert.Equal(t, "en-US", *(*res.Display)[0].Locale)
	assert.Equal(t, "Test Issuer", *(*res.Display)[0].Name)
	assert.Equal(t, "https://example.com", *(*res.Display)[0].Url)
	assert.Equal(t, "#000000", *(*res.Display)[0].TextColor)

	assert.Equal(t, "https://example.com/credentials-logo.png", *(*res.Display)[0].Logo.Url)
	assert.Equal(t, "Issuer Logo", *(*res.Display)[0].Logo.AltText)
}
