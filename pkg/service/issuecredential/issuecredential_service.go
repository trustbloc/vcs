/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package issuecredential_test -source=issuecredential_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry,vcStatusManager=MockVCStatusManager,vcStore=MockVCStore

package issuecredential

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

type vcStore interface {
	Put(profileName string, vc *verifiable.Credential) error
}

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...crypto.SigningOpts) (*verifiable.Credential, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type vcStatusManager interface {
	CreateStatusID(profileID string) (*StatusID, error)
}

type StatusID struct {
	Context  string
	VCStatus *verifiable.TypedID
}

type Config struct {
	VCStatusManager vcStatusManager
	VCStore         vcStore
	Crypto          vcCrypto
	KMSRegistry     kmsRegistry
}

type Service struct {
	vcStatusManager vcStatusManager
	crypto          vcCrypto
	kmsRegistry     kmsRegistry
	vcStore         vcStore
}

func New(config *Config) *Service {
	return &Service{
		vcStatusManager: config.VCStatusManager,
		crypto:          config.Crypto,
		kmsRegistry:     config.KMSRegistry,
		vcStore:         config.VCStore,
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
		Format:                  profile.VCConfig.Format,
		SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
		VCStatusListType:        profile.VCConfig.Status.Type,
	}

	var statusID *StatusID

	if !profile.VCConfig.Status.Disable {
		statusID, err = s.vcStatusManager.CreateStatusID(profile.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to add credential status: %w", err)
		}

		credential.Context = append(credential.Context, statusID.Context)
		credential.Status = statusID.VCStatus
	}

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
