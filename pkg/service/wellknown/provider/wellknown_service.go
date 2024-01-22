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
// # Note, that if the Credential Issuer wants to enforce use of signed metadata,
// it omits the respective metadata parameters from the unsigned part of the Credential Issuer metadata.
// In this case, HTTP response should be:
//
//	{
//	 "signed_metadata": "jwt_representation"
//	}
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
	// TODO: add support of internationalization and Accept-Language Header for this function.
	// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-11.2.2
	// For now, the following option from the spec supported:
	// - ignore the Accept-Language Header and send all supported languages or any chosen subset.
	host := s.externalHostURL
	if !strings.HasSuffix(host, "/") {
		host += "/"
	}

	credentialsConfigurationSupported := s.buildCredentialConfigurationsSupported(issuerProfile)

	issuerURL, _ := url.JoinPath(s.externalHostURL, "issuer", issuerProfile.ID, issuerProfile.Version)

	display := s.buildCredentialMetadataDisplay(
		issuerProfile.Name,
		issuerProfile.URL,
		issuerProfile.CredentialMetaData.Display,
	)

	final := &issuer.WellKnownOpenIDIssuerConfiguration{
		CredentialIssuer:                  &issuerURL,
		AuthorizationEndpoint:             lo.ToPtr(fmt.Sprintf("%soidc/authorize", host)),
		CredentialEndpoint:                lo.ToPtr(fmt.Sprintf("%soidc/credential", host)),
		BatchCredentialEndpoint:           nil, // no support for now
		DeferredCredentialEndpoint:        nil,
		NotificationEndpoint:              nil,
		CredentialResponseEncryption:      nil,
		CredentialIdentifiersSupported:    nil,
		SignedMetadata:                    nil,
		Display:                           lo.ToPtr(display),
		CredentialConfigurationsSupported: credentialsConfigurationSupported,

		CredentialAckEndpoint:  lo.ToPtr(fmt.Sprintf("%soidc/acknowledgement", host)),
		TokenEndpoint:          lo.ToPtr(fmt.Sprintf("%soidc/token", host)),
		ResponseTypesSupported: lo.ToPtr([]string{"code"}),
	}

	if issuerProfile.OIDCConfig != nil {
		if issuerProfile.OIDCConfig.EnableDynamicClientRegistration {
			regURL, _ := url.JoinPath(host, "oidc", issuerProfile.ID, issuerProfile.Version, "register")

			final.RegistrationEndpoint = lo.ToPtr(regURL)
		}

		final.TokenEndpointAuthMethodsSupported = lo.ToPtr(issuerProfile.OIDCConfig.TokenEndpointAuthMethodsSupported)
		final.ScopesSupported = lo.ToPtr(issuerProfile.OIDCConfig.ScopesSupported)
		final.GrantTypesSupported = lo.ToPtr(issuerProfile.OIDCConfig.GrantTypesSupported)
		final.PreAuthorizedGrantAnonymousAccessSupported =
			lo.ToPtr(issuerProfile.OIDCConfig.PreAuthorizedGrantAnonymousAccessSupported)
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

func (s *Service) buildCredentialMetadataDisplay(
	issuerProfileName, issuerProfileURL string,
	issuerProfileDisplay []*profileapi.CredentialDisplay,
) []issuer.CredentialDisplay {
	var display []issuer.CredentialDisplay
	if issuerProfileDisplay != nil {
		display = make([]issuer.CredentialDisplay, 0, len(issuerProfileDisplay))

		for _, d := range issuerProfileDisplay {
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
					Uri:     d.Logo.URL,
				}
			}

			display = append(display, credentialDisplay)
		}
	} else {
		display = []issuer.CredentialDisplay{
			{
				Locale: lo.ToPtr("en-US"),
				Name:   lo.ToPtr(issuerProfileName),
				Url:    lo.ToPtr(issuerProfileURL),
			},
		}
	}

	return display
}

func (s *Service) buildCredentialConfigurationsSupported(
	issuerProfile *profileapi.Issuer,
) *issuer.WellKnownOpenIDIssuerConfiguration_CredentialConfigurationsSupported {
	credentialsConfigurationSupported := &issuer.WellKnownOpenIDIssuerConfiguration_CredentialConfigurationsSupported{}
	for _, credentialSupported := range issuerProfile.CredentialMetaData.CredentialsSupported {
		var cryptographicBindingMethodsSupported, cryptographicSuitesSupported []string

		if issuerProfile.VCConfig != nil {
			cryptographicBindingMethodsSupported = []string{string(issuerProfile.VCConfig.DIDMethod)}
			cryptographicSuitesSupported = []string{string(issuerProfile.VCConfig.KeyType)}
		}

		display := lo.Map(credentialSupported.Display,
			func(profileapiDisplay profileapi.CredentialDisplay, index int) issuer.CredentialDisplay {
				var logo *issuer.Logo
				if profileapiDisplay.Logo != nil {
					logo = &issuer.Logo{
						AltText: lo.ToPtr(profileapiDisplay.Logo.AlternativeText),
						Uri:     profileapiDisplay.Logo.URL,
					}
				}
				return issuer.CredentialDisplay{
					BackgroundColor: lo.ToPtr(profileapiDisplay.BackgroundColor),
					Locale:          lo.ToPtr(profileapiDisplay.Locale),
					Logo:            logo,
					Name:            lo.ToPtr(profileapiDisplay.Name),
					TextColor:       lo.ToPtr(profileapiDisplay.TextColor),
					Url:             lo.ToPtr(profileapiDisplay.URL),
				}
			})

		credentialDefinition := &issuer.CredentialConfigurationsSupportedDefinition{
			CredentialSubject: lo.ToPtr(credentialSupported.CredentialSubject),
			Type:              credentialSupported.Types,
		}

		key := lo.Filter(credentialSupported.Types, func(item string, index int) bool {
			return item != "VerifiableCredential"
		})

		credentialsConfigurationSupported.Set(key[0], issuer.CredentialConfigurationsSupported{
			Format:                               credentialSupported.Format,
			Scope:                                nil,
			CryptographicBindingMethodsSupported: lo.ToPtr(cryptographicBindingMethodsSupported),
			CryptographicSuitesSupported:         lo.ToPtr(cryptographicSuitesSupported),
			ProofTypes:                           lo.ToPtr([]string{"jwt"}),
			Display:                              lo.ToPtr(display),
			CredentialDefinition:                 credentialDefinition,
		})
	}

	return credentialsConfigurationSupported
}
