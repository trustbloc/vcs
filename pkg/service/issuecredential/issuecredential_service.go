/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package issuecredential_test -source=issuecredential_service.go -mock_names profileService=MockProfileService,kmsRegistry=MockKMSRegistry,vcStatusManager=MockVCStatusManager

package issuecredential

import (
	"context"
	"fmt"

	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	defaultCredentialPrefix = "urn:uuid:" //nolint:gosec
)

// signingOpts holds options for the signing credential.
type issueCredentialOpts struct {
	transactionID string
	cryptoOpts    []crypto.SigningOpts
}

// Opts is signing credential option.
type Opts func(opts *issueCredentialOpts)

// WithTransactionID is an option to pass transactionID.
func WithTransactionID(transactionID string) Opts {
	return func(opts *issueCredentialOpts) {
		opts.transactionID = transactionID
	}
}

// WithCryptoOpts is an option to pass crypto.SigningOpts.
func WithCryptoOpts(cryptoOpts []crypto.SigningOpts) Opts {
	return func(opts *issueCredentialOpts) {
		opts.cryptoOpts = cryptoOpts
	}
}

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...crypto.SigningOpts) (*verifiable.Credential, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type vcStatusManager interface {
	CreateStatusListEntry(
		ctx context.Context,
		profileID string,
		profileVersion string,
		credentialMetadata *credentialstatus.CredentialMetadata,
	) (*credentialstatus.StatusListEntry, error)
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

func (s *Service) IssueCredential(
	ctx context.Context,
	credential *verifiable.Credential,
	profile *profileapi.Issuer,
	opts ...Opts,
) (*verifiable.Credential, error) {
	options := &issueCredentialOpts{}
	for _, f := range opts {
		f(options)
	}

	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return nil, fmt.Errorf("get kms: %w", err)
	}

	signer := &vc.Signer{
		DID:                     profile.SigningDID.DID,
		Creator:                 profile.SigningDID.Creator,
		KMSKeyID:                profile.SigningDID.KMSKeyID,
		SignatureType:           profile.VCConfig.SigningAlgorithm,
		KeyType:                 profile.VCConfig.KeyType,
		KMS:                     kms,
		Format:                  profile.VCConfig.Format,
		SignatureRepresentation: profile.VCConfig.SignatureRepresentation,
		VCStatusListType:        profile.VCConfig.Status.Type,
		SDJWT:                   profile.VCConfig.SDJWT,
		DataIntegrityProof:      profile.VCConfig.DataIntegrityProof,
	}

	var statusListEntry *credentialstatus.StatusListEntry

	// update credential prefix.
	credential = vcutil.PrependCredentialPrefix(credential, defaultCredentialPrefix)
	credentialContext := credential.Contents().Context
	// update credential issuer
	credential = credential.WithModifiedIssuer(vcutil.CreateIssuer(profile.SigningDID.DID, profile.Name))

	if !profile.VCConfig.Status.Disable {
		credentialMetadata := &credentialstatus.CredentialMetadata{
			CredentialID:   credential.Contents().ID,
			Issuer:         credential.Contents().Issuer.ID,
			CredentialType: credential.Contents().Types,
			TransactionID:  options.transactionID,
			IssuanceDate:   credential.Contents().Issued,
			ExpirationDate: credential.Contents().Expired,
		}

		statusListEntry, err = s.vcStatusManager.CreateStatusListEntry(
			ctx, profile.ID, profile.Version, credentialMetadata)
		if err != nil {
			return nil, fmt.Errorf("add credential status: %w", err)
		}

		credentialContext = append(credentialContext, statusListEntry.Context)
		credential = credential.WithModifiedStatus(statusListEntry.TypedID)
	}

	// update context
	credentialContext = vcutil.AppendSignatureTypeContext(credentialContext, profile.VCConfig.SigningAlgorithm)
	credential = credential.WithModifiedContext(credentialContext)

	// sign the credential
	signedVC, err := s.crypto.SignCredential(signer, credential, options.cryptoOpts...)
	if err != nil {
		return nil, fmt.Errorf("sign credential: %w", err)
	}

	return signedVC, nil
}
