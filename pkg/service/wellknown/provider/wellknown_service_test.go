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
				checkWellKnownOpenIDIssuerConfiguration(t, res, true, true)
				checkWellKnownOpenIDIssuerConfigurationDisplayPropertyExist(t, *res.Display)

				assert.Equal(t, "aa.bb.cc", jwt)
				assert.Nil(t, err)
			},
		},
		{
			name: "Success disabled DynamicClientRegistration",
			setup: func() {
				mockTestIssuerProfile = loadProfile(t)
				mockTestIssuerProfile.OIDCConfig.EnableDynamicClientRegistration = false

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
				checkWellKnownOpenIDIssuerConfiguration(t, res, true, false)
				checkWellKnownOpenIDIssuerConfigurationDisplayPropertyExist(t, *res.Display)

				assert.Equal(t, "aa.bb.cc", jwt)
				assert.Nil(t, err)
			},
		},
		{
			name: "Success signed issuer metadata is not supported",
			setup: func() {
				externalHostURL = "https://example.com"
				mockTestIssuerProfile = loadProfile(t)
				mockTestIssuerProfile.OIDCConfig.SignedIssuerMetadataSupported = false

				mockKMSRegistry = NewMockKMSRegistry(gomock.NewController(t))
				mockCryptoJWTSigner = NewMockCryptoJWTSigner(gomock.NewController(t))
			},
			check: func(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration, jwt string, err error) {
				checkWellKnownOpenIDIssuerConfiguration(t, res, true, true)
				checkWellKnownOpenIDIssuerConfigurationDisplayPropertyExist(t, *res.Display)

				assert.Empty(t, "", jwt)
				assert.Nil(t, err)
			},
		},
		{
			name: "Success OIDCConfig and display are empty",
			setup: func() {
				mockTestIssuerProfile = loadProfile(t)
				mockTestIssuerProfile.OIDCConfig = nil
				mockTestIssuerProfile.CredentialMetaData.Display = nil

				mockKMSRegistry = NewMockKMSRegistry(gomock.NewController(t))
				mockCryptoJWTSigner = NewMockCryptoJWTSigner(gomock.NewController(t))
			},
			check: func(t *testing.T, res *issuer.WellKnownOpenIDIssuerConfiguration, jwt string, err error) {
				checkWellKnownOpenIDIssuerConfiguration(t, res, false, false)
				checkWellKnownOpenIDIssuerConfigurationDisplayPropertyNotExist(t, *res.Display)

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

func loadProfile(t *testing.T) *profileapi.Issuer {
	t.Helper()

	var profile *profileapi.Issuer
	assert.NoError(t, json.Unmarshal(profileJSON, &profile))

	return profile
}

func checkWellKnownOpenIDIssuerConfiguration(
	t *testing.T,
	res *issuer.WellKnownOpenIDIssuerConfiguration,
	includedOIDCConfig, includedClientRegistration bool,
) {
	t.Helper()

	assert.Equal(t, "https://example.com/oidc/authorize", res.AuthorizationEndpoint)
	assert.Nil(t, res.BatchCredentialEndpoint)
	assert.Equal(t, "https://example.com/oidc/credential", res.CredentialEndpoint)
	assert.Equal(t, "https://example.com/issuer/profileID/profileVersion", res.CredentialIssuer)

	assert.Len(t, res.CredentialsSupported, 1)
	resMapped := (res.CredentialsSupported)[0].(map[string]interface{}) //nolint
	assert.Equal(t, "VerifiedEmployee_JWT", resMapped["id"])
	assert.Equal(t, []string{"orb"}, resMapped["cryptographic_binding_methods_supported"])
	assert.Equal(t, []string{"ECDSASecp256k1DER"}, resMapped["cryptographic_suites_supported"])
	assert.Equal(t, []string{"code"}, res.ResponseTypesSupported)

	if includedOIDCConfig {
		assert.Equal(t, []string{"grantType1", "grantType2"}, res.GrantTypesSupported)
		assert.Equal(t, []string{"scope1", "scope1"}, res.ScopesSupported)
		assert.Equal(t, []string{"none", "attest_jwt_client_auth"}, res.TokenEndpointAuthMethodsSupported)
		assert.True(t, res.PreAuthorizedGrantAnonymousAccessSupported)

		if includedClientRegistration {
			assert.Equal(t,
				"https://example.com/oidc/profileID/profileVersion/register",
				*res.RegistrationEndpoint)
		} else {
			assert.Nil(t, res.RegistrationEndpoint)
		}
	} else {
		assert.Nil(t, res.GrantTypesSupported)
		assert.Nil(t, res.ScopesSupported)
		assert.False(t, res.PreAuthorizedGrantAnonymousAccessSupported)
		assert.Nil(t, res.RegistrationEndpoint)
		assert.Nil(t, res.TokenEndpointAuthMethodsSupported)
	}
}

func checkWellKnownOpenIDIssuerConfigurationDisplayPropertyExist(t *testing.T, display []issuer.CredentialDisplay) {
	t.Helper()

	assert.Equal(t, "#FFFFFF", *display[0].BackgroundColor)
	assert.Equal(t, "en-US", *display[0].Locale)
	assert.Equal(t, "Test Issuer", *display[0].Name)
	assert.Equal(t, "https://example.com", *display[0].Url)
	assert.Equal(t, "#000000", *display[0].TextColor)

	assert.Equal(t, "https://example.com/credentials-logo.png", *display[0].Logo.Url)
	assert.Equal(t, "Issuer Logo", *display[0].Logo.AltText)
}

func checkWellKnownOpenIDIssuerConfigurationDisplayPropertyNotExist(t *testing.T, display []issuer.CredentialDisplay) {
	t.Helper()

	assert.Nil(t, display[0].BackgroundColor)
	assert.Nil(t, display[0].Logo)
	assert.Nil(t, display[0].TextColor)
	assert.Empty(t, display[0].Url)
	assert.Equal(t, "en-US", *(display)[0].Locale)
	assert.Equal(t, "random_name", *(display)[0].Name)
}
