/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package issuecredential -source=issuecredential_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry,vcStatusManager=MockVCStatusManager

package issuecredential

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

type vcStatusManager interface {
	CreateStatusID(vcSigner *vc.Signer, url string) (*verifiable.TypedID, error)
	GetCredentialStatusURL(issuerProfileURL, issuerProfileID, statusID string) (string, error)
}

type vcCrypto interface {
	SignCredentialLDP(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...crypto.SigningOpts) (*verifiable.Credential, error)
	SignCredentialJWT(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...crypto.SigningOpts) (*verifiable.Credential, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type Config struct {
	VCStatusManager vcStatusManager
	Crypto          vcCrypto
	KMSRegistry     kmsRegistry
}

type Service struct {
	vcStatusManager vcStatusManager
	crypto          vcCrypto
	kmsRegistry     kmsRegistry
}

func New(config *Config) *Service {
	return &Service{
		vcStatusManager: config.VCStatusManager,
		crypto:          config.Crypto,
		kmsRegistry:     config.KMSRegistry,
	}
}

func (s *Service) IssueCredential(credential *verifiable.Credential,
	issuerSigningOpts []crypto.SigningOpts,
	profile *profileapi.Issuer) (*verifiable.Credential, error) {
	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kms: %w", err)
	}

	signer := &vc.Signer{
		DID:                     profile.SigningDID.DID,
		Creator:                 profile.SigningDID.Creator,
		SignatureType:           profile.VCConfig.SigningAlgorithm,
		KeyType:                 profile.VCConfig.KeyType,
		KMS:                     kms,
		SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
	}

	// todo: adjust s.vcStatusManager.CreateStatusID() to be able to work with JWT
	// issue: https://github.com/trustbloc/vcs/issues/826
	if profile.VCConfig.Format == vcsverifiable.Ldp {
		var status *verifiable.TypedID
		var statusURL string

		statusURL, err = s.vcStatusManager.GetCredentialStatusURL(profile.URL, profile.ID, "")
		if err != nil {
			return nil, fmt.Errorf("failed to create status URL: %w", err)
		}

		status, err = s.vcStatusManager.CreateStatusID(signer, statusURL)
		if err != nil {
			return nil, fmt.Errorf("failed to add credential status: %w", err)
		}

		credential.Context = append(credential.Context, credentialstatus.Context)
		credential.Status = status
	}

	// update context
	vcutil.UpdateSignatureTypeContext(credential, profile.VCConfig.SigningAlgorithm)

	// update credential issuer
	vcutil.UpdateIssuer(credential, profile.SigningDID.DID, profile.Name, true)

	// sign the credential
	signedVC, err := s.Sign(profile.VCConfig.Format, signer, credential, issuerSigningOpts)

	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	return signedVC, nil
}

func (s *Service) Sign(
	format vcsverifiable.Format,
	signer *vc.Signer,
	credential *verifiable.Credential,
	issuerSigningOpts []crypto.SigningOpts,
) (*verifiable.Credential, error) {
	switch format {
	case vcsverifiable.Jwt:
		return s.crypto.SignCredentialJWT(signer, credential, issuerSigningOpts...)
	case vcsverifiable.Ldp:
		return s.crypto.SignCredentialLDP(signer, credential, issuerSigningOpts...)
	default:
		return nil, fmt.Errorf("unknown signature format %s", format)
	}
}
