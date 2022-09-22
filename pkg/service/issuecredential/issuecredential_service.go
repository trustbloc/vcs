/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package issuecredential -source=issuecredential_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry

package issuecredential

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	cslstatus "github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	"github.com/trustbloc/vcs/pkg/issuer"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
)

const (
	credentialStatus = "/credentials/status"
)

type vcStatusManager interface {
	CreateStatusID(vcSigner *vc.Signer, url string) (*verifiable.TypedID, error)
}

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
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
	profile *issuer.Profile,
	signingDID *issuer.SigningDID) (*verifiable.Credential, error) {
	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get kms: %w", err)
	}

	signer := &vc.Signer{
		DID:                     signingDID.DID,
		Creator:                 signingDID.Creator,
		SignatureType:           profile.VCConfig.SigningAlgorithm,
		KMS:                     kms,
		SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
	}

	status, err := s.vcStatusManager.CreateStatusID(signer, profile.URL+profile.ID+credentialStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to add credential status: %w", err)
	}

	credential.Context = append(credential.Context, cslstatus.Context)
	credential.Status = status

	// update context
	vcutil.UpdateSignatureTypeContext(credential, profile.VCConfig.SigningAlgorithm)

	// update credential issuer
	vcutil.UpdateIssuer(credential, signingDID.DID, profile.Name, true)

	// sign the credential
	signedVC, err := s.crypto.SignCredential(signer, credential, issuerSigningOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	return signedVC, nil
}
