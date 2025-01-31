/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
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
				keyMgr := mocks.NewMockVCSKeyManager(gomock.NewController(t))

				mockKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).
					DoAndReturn(func(config *vcskms.Config) (vcskms.VCSKeyManager, error) {
						assert.EqualValues(t, "local", config.KMSType)
						assert.EqualValues(t, "https://example.com", config.Endpoint)

						return keyMgr, nil
					})

				mockCryptoJWTSigner.EXPECT().NewJWTSigned(gomock.Any(), &vc.Signer{
					Creator:  "did:orb:bank_issuer#123",
					KMS:      keyMgr,
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

//nolint:lll
func checkWellKnownOpenIDIssuerConfiguration(
	t *testing.T,
	res *issuer.WellKnownOpenIDIssuerConfiguration,
	includedOIDCConfig, includedClientRegistration bool,
) {
	t.Helper()

	assert.Equal(t, "https://example.com/issuer/profileID/profileVersion", lo.FromPtr(res.CredentialIssuer))
	assert.Equal(t, "https://example.com/oidc/authorize", lo.FromPtr(res.AuthorizationEndpoint))
	assert.Equal(t, "https://example.com/oidc/credential", lo.FromPtr(res.CredentialEndpoint))
	assert.Equal(t, "https://example.com/oidc/batch_credential", lo.FromPtr(res.BatchCredentialEndpoint))
	assert.Nil(t, res.DeferredCredentialEndpoint)
	assert.Nil(t, res.CredentialResponseEncryption)
	assert.Nil(t, res.CredentialIdentifiersSupported)
	assert.Nil(t, res.SignedMetadata)

	assert.Len(t, *res.CredentialConfigurationsSupported, 1)

	for credentialType, credentialConfigurationSupported := range *res.CredentialConfigurationsSupported {
		assert.Equal(t, map[string]interface{}{
			"org.iso.18013.5.1.aamva": map[string]interface{}{
				"organ_donor": map[string]interface{}{},
			},
		}, lo.FromPtr(credentialConfigurationSupported.Claims))

		definition := credentialConfigurationSupported.CredentialDefinition

		expectedKey := lo.Filter(definition.Type, func(item string, index int) bool {
			return item != "VerifiableCredential"
		})

		assert.Equal(t, expectedKey[0], credentialType)
		assert.Equal(t, 7, len(lo.FromPtr(definition.CredentialSubject)))
		assert.Equal(t, []string{"https://example.com/context/1"}, lo.FromPtr(definition.Context))

		assert.Equal(t, []string{"orb"}, lo.FromPtr(credentialConfigurationSupported.CryptographicBindingMethodsSupported))
		assert.Equal(t, []string{"ECDSASecp256k1DER"}, lo.FromPtr(credentialConfigurationSupported.CredentialSigningAlgValuesSupported))

		credentialConfigurationSupportedDisplay := lo.FromPtr(credentialConfigurationSupported.Display)
		assert.Equal(t, 1, len(credentialConfigurationSupportedDisplay))
		assert.Equal(t, "#12107c", lo.FromPtr(credentialConfigurationSupportedDisplay[0].BackgroundColor))
		assert.Equal(t, "en-US", lo.FromPtr(credentialConfigurationSupportedDisplay[0].Locale))
		assert.Equal(t, &issuer.Logo{
			AltText: lo.ToPtr("a square logo of a employee verification"),
			Uri:     "https://example.com/public/logo.png",
		}, credentialConfigurationSupportedDisplay[0].Logo)
		assert.Equal(t, "Verified Employee", lo.FromPtr(credentialConfigurationSupportedDisplay[0].Name))
		assert.Equal(t, "#FFFFFF", lo.FromPtr(credentialConfigurationSupportedDisplay[0].TextColor))
		assert.Equal(t, "", lo.FromPtr(credentialConfigurationSupportedDisplay[0].Url))

		assert.Equal(t, "doctype1", lo.FromPtr(credentialConfigurationSupported.Doctype))
		assert.Equal(t, "ldp_vc", credentialConfigurationSupported.Format)
		assert.Equal(t, []string{"claimName1", "claimName2", "claimName3"}, lo.FromPtr(credentialConfigurationSupported.Order))

		expectedProofTypeSupported := map[string]issuer.ProofTypeSupported{
			"jwt": {
				ProofSigningAlgValuesSupported: []string{"ECDSASecp256k1DER"},
			},
		}

		assert.Equal(t, expectedProofTypeSupported, lo.FromPtr(credentialConfigurationSupported.ProofTypesSupported))
		assert.Equal(t, "VerifiedEmployeeCredential", lo.FromPtr(credentialConfigurationSupported.Scope))
		assert.Equal(t, "vct1", lo.FromPtr(credentialConfigurationSupported.Vct))
	}

	assert.Equal(t, "https://example.com/oidc/notification", lo.FromPtr(res.NotificationEndpoint))
	assert.Equal(t, "https://example.com/oidc/token", lo.FromPtr(res.TokenEndpoint))
	assert.Equal(t, []string{"code"}, lo.FromPtr(res.ResponseTypesSupported))

	if includedOIDCConfig {
		assert.Equal(t, []string{"grantType1", "grantType2"}, lo.FromPtr(res.GrantTypesSupported))
		assert.Equal(t, []string{"scope1", "scope1"}, lo.FromPtr(res.ScopesSupported))
		assert.Equal(t, []string{"none", "attest_jwt_client_auth"}, lo.FromPtr(res.TokenEndpointAuthMethodsSupported))
		assert.True(t, lo.FromPtr(res.PreAuthorizedGrantAnonymousAccessSupported))

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
		assert.Nil(t, res.PreAuthorizedGrantAnonymousAccessSupported)
		assert.Nil(t, res.RegistrationEndpoint)
		assert.Nil(t, res.TokenEndpointAuthMethodsSupported)
	}
}

func TestBuildWithDynamic(t *testing.T) {
	t.Run("dynamic err", func(t *testing.T) {
		store := NewMockdynamicWellKnownStore(gomock.NewController(t))

		srv := NewService(&Config{
			DynamicWellKnownStore: store,
		})

		store.EXPECT().Get(gomock.Any(), "12345").
			Return(nil, errors.New("unexpected err"))

		resp, err := srv.getOpenIDIssuerConfig(&profileapi.Issuer{
			ID:                 "12345",
			CredentialMetaData: &profileapi.CredentialMetaData{},
			OIDCConfig: &profileapi.OIDCConfig{
				DynamicWellKnownSupported: true,
			},
			VCConfig: &profileapi.VCConfig{
				KeyType: "someKey",
			},
		})

		assert.ErrorContains(t, err, "unexpected err")
		assert.Nil(t, resp)
	})
	t.Run("success", func(t *testing.T) {
		store := NewMockdynamicWellKnownStore(gomock.NewController(t))

		srv := NewService(&Config{
			DynamicWellKnownStore: store,
		})

		store.EXPECT().Get(gomock.Any(), "12345").
			Return(map[string]*profileapi.CredentialsConfigurationSupported{
				"a": {
					CredentialDefinition: &profileapi.CredentialDefinition{
						Type: []string{"SomeType"},
					},
				},
			}, nil)

		resp, err := srv.getOpenIDIssuerConfig(&profileapi.Issuer{
			ID:                 "12345",
			CredentialMetaData: &profileapi.CredentialMetaData{},
			OIDCConfig: &profileapi.OIDCConfig{
				DynamicWellKnownSupported: true,
			},
			VCConfig: &profileapi.VCConfig{
				KeyType: "someKey",
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp)

		assert.Len(t, *resp.CredentialConfigurationsSupported, 1)
		assert.EqualValues(
			t,
			[]string{"SomeType"},
			lo.FromPtr(resp.CredentialConfigurationsSupported)["a"].CredentialDefinition.Type,
		)
	})
}

func TestUpsert(t *testing.T) {
	store := NewMockdynamicWellKnownStore(gomock.NewController(t))

	srv := NewService(&Config{
		DynamicWellKnownStore: store,
	})

	val := &profileapi.CredentialsConfigurationSupported{}

	store.EXPECT().Upsert(gomock.Any(), "profileID", gomock.Any()).
		DoAndReturn(func(
			ctx context.Context,
			s string,
			m map[string]*profileapi.CredentialsConfigurationSupported,
		) error {
			assert.Len(t, m, 1)
			assert.Equal(t, val, m["key1"])
			return nil
		})
	assert.NoError(t, srv.AddDynamicConfiguration(context.TODO(), "profileID", "key1",
		val))
}

func checkWellKnownOpenIDIssuerConfigurationDisplayPropertyExist(t *testing.T, display []issuer.CredentialDisplay) {
	t.Helper()

	assert.Equal(t, "#FFFFFF", *display[0].BackgroundColor)
	assert.Equal(t, "en-US", *display[0].Locale)
	assert.Equal(t, "Test Issuer", *display[0].Name)
	assert.Equal(t, "https://example.com", *display[0].Url)
	assert.Equal(t, "#000000", *display[0].TextColor)

	assert.Equal(t, "https://example.com/credentials-logo.png", display[0].Logo.Uri)
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
