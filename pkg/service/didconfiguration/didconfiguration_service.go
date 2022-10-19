/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package didconfiguration -source=didconfiguration_service.go -mock_names kmsRegistry=MockKmsRegistry,verifierProfileService=MockVerifierProfileService,issuerProfileService=MockIssuerProfileService,vcCrypto=MockVCCrypto

package didconfiguration

import (
	"context"
	"errors"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

const (
	didConfigurationContextURL    = "https://identity.foundation/.well-known/did-configuration/v1" //nolint:gosec
	w3CredentialsURL              = "https://www.w3.org/2018/credentials/v1"                       //nolint:gosec
	vcTypeVerifiableCredential    = "VerifiableCredential"                                         //nolint:gosec
	vcTypeDomainLinkageCredential = "DomainLinkageCredential"                                      //nolint:gosec
)

type verifierProfileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Verifier, error)
}

type issuerProfileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...crypto.SigningOpts) (*verifiable.Credential, error)
}

type ProfileType string

const (
	ProfileTypeIssuer   = ProfileType("issuer")
	ProfileTypeVerifier = ProfileType("verifier")
)

type Config struct {
	VerifierProfileService verifierProfileService
	IssuerProfileService   issuerProfileService
	Crypto                 vcCrypto
	KmsRegistry            kmsRegistry
}

type Service struct {
	verifierProfileService verifierProfileService
	issuerProfileService   issuerProfileService
	vcCrypto               vcCrypto
	kmsRegistry            kmsRegistry
}

type DidConfiguration struct {
	Context    string        `json:"@context"`
	LinkedDiDs []interface{} `json:"linked_dids"`
}

func New(
	config *Config,
) *Service {
	return &Service{
		verifierProfileService: config.VerifierProfileService,
		issuerProfileService:   config.IssuerProfileService,
		vcCrypto:               config.Crypto,
		kmsRegistry:            config.KmsRegistry,
	}
}

func (s *Service) DidConfig(
	ctx context.Context,
	profileType ProfileType,
	profileID string,
) (*DidConfiguration, error) {
	cred := s.getBaseCredentials()

	var format vcsverifiable.Format
	var signer *vc.Signer

	switch profileType {
	case ProfileTypeVerifier:
		profile, err := s.verifierProfileService.GetProfile(profileID)
		if err != nil {
			return nil, resterr.NewValidationError(resterr.SystemError, "profileID",
				err)
		}

		if profile.OIDCConfig == nil {
			return nil, errors.New("oidc config is required for verifier")
		}

		format = vcsverifiable.Jwt
		if profile.Checks != nil && len(profile.Checks.Credential.Format) > 0 {
			format = profile.Checks.Credential.Format[0]
		}

		cred.Issuer = verifiable.Issuer{
			ID: profile.SigningDID.DID,
		}
		cred.Subject = map[string]interface{}{
			"id":     profile.SigningDID.DID,
			"origin": profile.URL,
		}

		kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)

		if err != nil {
			return nil, err
		}

		signer = &vc.Signer{
			Format:        format,
			DID:           profile.SigningDID.DID,
			Creator:       profile.SigningDID.Creator,
			SignatureType: profile.OIDCConfig.ROSigningAlgorithm,
			KeyType:       profile.OIDCConfig.KeyType,
			KMS:           kms,
		}
	case ProfileTypeIssuer:
		profile, err := s.issuerProfileService.GetProfile(profileID)

		if err != nil {
			return nil, resterr.NewValidationError(resterr.SystemError, "profileID",
				err)
		}

		format = profile.VCConfig.Format
		cred.Issuer = verifiable.Issuer{
			ID: profile.SigningDID.DID,
		}
		cred.Subject = map[string]interface{}{
			"id":     profile.SigningDID.DID,
			"origin": profile.URL,
		}
		kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)

		if err != nil {
			return nil, err
		}

		signer = &vc.Signer{
			Format:                  format,
			DID:                     profile.SigningDID.DID,
			Creator:                 profile.SigningDID.Creator,
			SignatureType:           profile.VCConfig.SigningAlgorithm,
			KeyType:                 profile.VCConfig.KeyType,
			KMS:                     kms,
			SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
		}
	default:
		return nil, resterr.NewValidationError(resterr.InvalidValue, "profileType",
			errors.New("profileType should be verifier or issuer"))
	}
	cred, err := s.vcCrypto.SignCredential(signer, cred, []crypto.SigningOpts{}...)

	if err != nil {
		return nil, err
	}

	resp := &DidConfiguration{
		Context: didConfigurationContextURL,
	}

	if format == vcsverifiable.Jwt {
		resp.LinkedDiDs = append(resp.LinkedDiDs, cred.JWT)
	} else {
		resp.LinkedDiDs = append(resp.LinkedDiDs, cred)
	}

	return resp, nil
}

func (s *Service) getBaseCredentials() *verifiable.Credential {
	return &verifiable.Credential{
		Context: []string{
			w3CredentialsURL,
			didConfigurationContextURL,
		},
		Types: []string{
			vcTypeVerifiableCredential,
			vcTypeDomainLinkageCredential,
		},
		Issued:  util.NewTime(time.Now().UTC()),
		Expired: util.NewTime(time.Now().UTC()),
	}
}
