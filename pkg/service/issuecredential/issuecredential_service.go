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
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/storage"
)

type vcStatusManager interface {
	CreateStatusID(vcSigner *vc.Signer, url string) (*verifiable.TypedID, error)
	GetCredentialStatusURL(issuerProfileURL, issuerProfileID, statusID string) (string, error)
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
	StorageProvider storage.Provider
}

type Service struct {
	vcStatusManager vcStatusManager
	crypto          vcCrypto
	kmsRegistry     kmsRegistry
	vcStore         storage.VCStore
}

func New(config *Config) (*Service, error) {
	vcStore, err := config.StorageProvider.OpenVCStore()
	if err != nil {
		return nil, err
	}

	return &Service{
		vcStatusManager: config.VCStatusManager,
		crypto:          config.Crypto,
		kmsRegistry:     config.KMSRegistry,
		vcStore:         vcStore,
	}, nil
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
		Format:                  profile.VCConfig.Format,
		SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
	}

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

	// update context
	vcutil.UpdateSignatureTypeContext(credential, profile.VCConfig.SigningAlgorithm)

	// update credential issuer
	vcutil.UpdateIssuer(credential, profile.SigningDID.DID, profile.Name, true)

	// sign the credential
	signedVC, err := s.crypto.SignCredential(signer, credential, issuerSigningOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	// Store to DB
	err = s.vcStore.Put(profile.Name, signedVC)
	if err != nil {
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}

	return signedVC, nil
}
