/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package didconfiguration -source=didconfiguration_service.go -mock_names kmsRegistry=MockKmsRegistry,verifierProfileService=MockVerifierProfileService,issuerProfileService=MockIssuerProfileService,issueCredentialService=MockIssueCredentialService

package didconfiguration

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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

type verifierProfileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Verifier, error)
}

type issuerProfileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type issueCredentialService interface {
	Sign(
		format vcsverifiable.Format,
		signer *vc.Signer,
		credential *verifiable.Credential,
		issuerSigningOpts []crypto.SigningOpts,
	) (*verifiable.Credential, error)
}

type ProfileType string

const (
	ProfileTypeIssuer   = ProfileType("issuer")
	ProfileTypeVerifier = ProfileType("verifier")
)

type Config struct {
	VerifierProfileService  verifierProfileService
	IssuerProfileService    issuerProfileService
	IssuerCredentialService issueCredentialService
	KmsRegistry             kmsRegistry
}

type Service struct {
	verifierProfileService  verifierProfileService
	issuerProfileService    issuerProfileService
	issuerCredentialService issueCredentialService
	kmsRegistry             kmsRegistry
}

type DidConfiguration struct {
	Context    string        `json:"@context"`
	LinkedDiDs []interface{} `json:"linked_dids"`
}

func New(
	config *Config,
) *Service {
	return &Service{
		verifierProfileService:  config.VerifierProfileService,
		issuerProfileService:    config.IssuerProfileService,
		issuerCredentialService: config.IssuerCredentialService,
		kmsRegistry:             config.KmsRegistry,
	}
}

func (s *Service) DidConfig(
	ctx context.Context,
	profileType ProfileType,
	profileID string,
	contextUrl string,
) (*DidConfiguration, error) {
	u, err := url.Parse(contextUrl)

	if err != nil {
		return nil, err
	}

	cred := &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://identity.foundation/.well-known/did-configuration/v1",
		},
		Types: []string{
			"VerifiableCredential",
			"DomainLinkageCredential",
		},
		Issued: util.NewTime(time.Now().UTC()),
	}

	format := vcsverifiable.Ldp

	var signer *vc.Signer

	switch profileType {
	case ProfileTypeVerifier:
		if profile, err := s.verifierProfileService.GetProfile(profileID); err != nil {
			return nil, resterr.NewValidationError(resterr.SystemError, "profileID",
				err)
		} else {
			cred.Issuer = verifiable.Issuer{
				ID: profile.SigningDID.DID,
			}
			cred.Subject = map[string]interface{}{
				"id":     profile.SigningDID.DID, // todo nothing in JSON ???
				"origin": fmt.Sprintf("%s://%s", u.Scheme, u.Hostname()),
			}

			kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)

			if err != nil {
				return nil, err
			}

			signer = &vc.Signer{
				DID:           profile.SigningDID.DID,
				Creator:       profile.SigningDID.Creator,
				SignatureType: vcsverifiable.Ed25519Signature2018,
				KeyType:       kms.SupportedKeyTypes()[0],
				KMS:           kms,
			}
		}
	case ProfileTypeIssuer:
		if profile, err := s.issuerProfileService.GetProfile(profileID); err != nil {
			return nil, resterr.NewValidationError(resterr.SystemError, "profileID",
				err)
		} else {
			format = profile.VCConfig.Format

			cred.Issuer = verifiable.Issuer{
				ID: profile.SigningDID.DID,
			}
			cred.Subject = map[string]interface{}{
				"id":     profile.SigningDID.DID,
				"origin": fmt.Sprintf("%s://%s", u.Scheme, u.Hostname()),
			}
			kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)

			if err != nil {
				return nil, err
			}

			signer = &vc.Signer{
				DID:                     profile.SigningDID.DID,
				Creator:                 profile.SigningDID.Creator,
				SignatureType:           profile.VCConfig.SigningAlgorithm,
				KeyType:                 profile.VCConfig.KeyType,
				KMS:                     kms,
				SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
			}
		}
	default:
		return nil, resterr.NewValidationError(resterr.InvalidValue, "profileType",
			errors.New("profileType should be verifier or issuer"))
	}

	cred, err = s.issuerCredentialService.Sign(format, signer, cred, nil)

	if err != nil {
		return nil, err
	}

	resp := &DidConfiguration{
		Context: contextUrl,
	}

	if format == vcsverifiable.Jwt {
		resp.LinkedDiDs = append(resp.LinkedDiDs, cred.JWT)
	} else {
		resp.LinkedDiDs = append(resp.LinkedDiDs, cred)
	}

	return resp, nil
}
