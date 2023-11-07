/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination wellknown_service_mocks_test.go -package provider -source=wellknown_service.go -mock_names kmsRegistry=MockKMSRegistry,cryptoJWTSigner=MockCryptoJWTSigner

package provider

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/samber/lo"

	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

type kmsRegistry interface {
	GetKeyManager(config *kms.Config) (kms.VCSKeyManager, error)
}

type cryptoJWTSigner interface {
	NewJWTSigned(claims interface{}, signerData *vc.Signer) (string, error)
}

// JWTWellKnownOpenIDIssuerConfigurationClaims is JWT Claims extension
// by WellKnownOpenIDIssuerConfiguration (with custom "well_known_openid_issuer_configuration" claim).
type JWTWellKnownOpenIDIssuerConfigurationClaims struct {
	*jwt.Claims

	WellKnownOpenIDIssuerConfiguration *issuer.WellKnownOpenIDIssuerConfiguration `json:"well_known_openid_issuer_configuration,omitempty"` //nolint:lll
}

type Config struct {
	ExternalHostURL string
	KMSRegistry     kmsRegistry
	CryptoJWTSigner cryptoJWTSigner
}

type Service struct {
	externalHostURL string
	kmsRegistry     kmsRegistry
	cryptoJWTSigner cryptoJWTSigner
}

func NewService(config *Config) *Service {
	return &Service{
		externalHostURL: config.ExternalHostURL,
		kmsRegistry:     config.KMSRegistry,
		cryptoJWTSigner: config.CryptoJWTSigner,
	}
}

// GetOpenIDCredentialIssuerConfig returns issuer.WellKnownOpenIDIssuerConfiguration object, and
// it's JWT signed representation, if this feature is enabled for specific profile.
//
// Used for creating GET .well-known/openid-credential-issuer VCS IDP response.
func (s *Service) GetOpenIDCredentialIssuerConfig(
	issuerProfile *profileapi.Issuer) (*issuer.WellKnownOpenIDIssuerConfiguration, string, error) {
	var (
		jwtSignedIssuerMetadata string
		err                     error
	)

	issuerMetadata := s.getOpenIDIssuerConfig(issuerProfile)

	if issuerProfile.OIDCConfig != nil && issuerProfile.OIDCConfig.SignedIssuerMetadataSupported {
		jwtSignedIssuerMetadata, err = s.signIssuerMetadata(issuerProfile, issuerMetadata)
		if err != nil {
			return nil, "", err
		}
	}

	return issuerMetadata, jwtSignedIssuerMetadata, nil
}

func (s *Service) getOpenIDIssuerConfig(issuerProfile *profileapi.Issuer) *issuer.WellKnownOpenIDIssuerConfiguration {
	host := s.externalHostURL
	if !strings.HasSuffix(host, "/") {
		host += "/"
	}

	var finalCredentials []interface{}
	for _, t := range issuerProfile.CredentialMetaData.CredentialsSupported {
		if issuerProfile.VCConfig != nil {
			t["cryptographic_binding_methods_supported"] = []string{string(issuerProfile.VCConfig.DIDMethod)}
			t["cryptographic_suites_supported"] = []string{string(issuerProfile.VCConfig.KeyType)}
		}
		finalCredentials = append(finalCredentials, t)
	}

	var display []issuer.CredentialDisplay

	if issuerProfile.CredentialMetaData.Display != nil {
		display = make([]issuer.CredentialDisplay, 0, len(issuerProfile.CredentialMetaData.Display))

		for _, d := range issuerProfile.CredentialMetaData.Display {
			credentialDisplay := issuer.CredentialDisplay{
				BackgroundColor: lo.ToPtr(d.BackgroundColor),
				Locale:          lo.ToPtr(d.Locale),
				Name:            lo.ToPtr(d.Name),
				TextColor:       lo.ToPtr(d.TextColor),
				Url:             lo.ToPtr(d.URL),
			}

			if d.Logo != nil {
				credentialDisplay.Logo = &issuer.Logo{
					AltText: lo.ToPtr(d.Logo.AlternativeText),
					Url:     lo.ToPtr(d.Logo.URL),
				}
			}

			display = append(display, credentialDisplay)
		}
	} else {
		display = []issuer.CredentialDisplay{
			{
				Locale: lo.ToPtr("en-US"),
				Name:   lo.ToPtr(issuerProfile.Name),
				Url:    lo.ToPtr(issuerProfile.URL),
			},
		}
	}

	issuerURL, _ := url.JoinPath(s.externalHostURL, "issuer", issuerProfile.ID, issuerProfile.Version)

	final := &issuer.WellKnownOpenIDIssuerConfiguration{
		AuthorizationEndpoint:   fmt.Sprintf("%soidc/authorize", host),
		BatchCredentialEndpoint: nil, // no support for now
		CredentialEndpoint:      fmt.Sprintf("%soidc/credential", host),
		CredentialIssuer:        issuerURL,
		CredentialsSupported:    finalCredentials,
		Display:                 lo.ToPtr(display),
		ResponseTypesSupported: []string{
			"code",
		},
		TokenEndpoint: fmt.Sprintf("%soidc/token", host),
	}

	if issuerProfile.OIDCConfig != nil {
		final.GrantTypesSupported = issuerProfile.OIDCConfig.GrantTypesSupported
		final.ScopesSupported = issuerProfile.OIDCConfig.ScopesSupported
		final.PreAuthorizedGrantAnonymousAccessSupported = issuerProfile.OIDCConfig.PreAuthorizedGrantAnonymousAccessSupported
		final.TokenEndpointAuthMethodsSupported = issuerProfile.OIDCConfig.TokenEndpointAuthMethodsSupported

		if issuerProfile.OIDCConfig.EnableDynamicClientRegistration {
			regURL, _ := url.JoinPath(host, "oidc", issuerProfile.ID, issuerProfile.Version, "register")

			final.RegistrationEndpoint = lo.ToPtr(regURL)
		}
	}

	return final
}

func (s *Service) signIssuerMetadata(
	profile *profileapi.Issuer,
	meta *issuer.WellKnownOpenIDIssuerConfiguration,
) (string, error) {
	keyManager, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return "", fmt.Errorf("get kms: %w", err)
	}

	signerData := &vc.Signer{
		KeyType:       profile.VCConfig.KeyType,
		KMSKeyID:      profile.SigningDID.KMSKeyID,
		KMS:           keyManager,
		SignatureType: profile.VCConfig.SigningAlgorithm,
		Creator:       profile.SigningDID.Creator,
	}

	claims := &JWTWellKnownOpenIDIssuerConfigurationClaims{
		Claims: &jwt.Claims{
			Issuer:   profile.SigningDID.DID,
			Subject:  profile.SigningDID.DID,
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
		WellKnownOpenIDIssuerConfiguration: meta,
	}

	signedIssuerMetadata, err := s.cryptoJWTSigner.NewJWTSigned(claims, signerData)
	if err != nil {
		return "", fmt.Errorf("sign issuer metadata: %w", err)
	}

	return signedIssuerMetadata, nil
}
