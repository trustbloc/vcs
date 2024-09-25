/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslmanager

//go:generate mockgen -destination cslmanager_mocks_test.go -self_package github.com/trustbloc/pkg/cslmanager -package cslmanager -source=cslmanager.go -mock_names kmsRegistry=MockKMSRegistry,vcStatusStore=MockVCStatusStore

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

var logger = log.New("csl-list-manager")

type vcCrypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

type kmsRegistry interface {
	GetKeyManager(config *vcskms.Config) (vcskms.VCSKeyManager, error)
}

type cslVCStore interface {
	// GetCSLURL returns the public URL to the CSL.
	GetCSLURL(issuerProfileURL, externalIssuerProfileID string, statusListID credentialstatus.ListID) (string, error)
	// Upsert updates CSL VC wrapper.
	Upsert(ctx context.Context, cslURL string, wrapper *credentialstatus.CSLVCWrapper) error
}

type vcStatusStore interface {
	Put(
		ctx context.Context,
		profileID profileapi.ID,
		profileVersion profileapi.Version,
		credentialID string,
		typedID *verifiable.TypedID,
	) error
}

type Config struct {
	CSLVCStore    cslVCStore
	VCStatusStore vcStatusStore
	CSLIndexStore credentialstatus.CSLIndexStore
	ListSize      int
	Crypto        vcCrypto
	KMSRegistry   kmsRegistry
	ExternalURL   string
}

type Manager struct {
	cslIndexStore credentialstatus.CSLIndexStore
	vcStatusStore vcStatusStore
	cslVCStore    cslVCStore
	listSize      int
	crypto        vcCrypto
	kmsRegistry   kmsRegistry
	externalURL   string
	mutex         sync.RWMutex
}

// New returns new CSL list manager.
func New(config *Config) (*Manager, error) {
	return &Manager{
		cslIndexStore: config.CSLIndexStore,
		cslVCStore:    config.CSLVCStore,
		vcStatusStore: config.VCStatusStore,
		listSize:      config.ListSize,
		crypto:        config.Crypto,
		kmsRegistry:   config.KMSRegistry,
		externalURL:   config.ExternalURL,
	}, nil
}

// CreateCSLEntry creates CSL entry.
func (s *Manager) CreateCSLEntry(
	ctx context.Context,
	profile *profileapi.Issuer,
	credentialID string,
) (*credentialstatus.StatusListEntry, error) {
	logger.Debugc(ctx, "CSL Manager - CreateCSLEntry",
		logfields.WithProfileID(profile.ID), logfields.WithProfileVersion(profile.Version))

	cslURL, statusBitIndex, err := s.getProfileCSLAndAssignedIndex(ctx, profile)
	if err != nil {
		return nil, err
	}

	vcStatusProcessor, err := statustype.GetVCStatusProcessor(profile.VCConfig.Status.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to get VC status processor: %w", err)
	}

	statusListEntry := &credentialstatus.StatusListEntry{
		TypedID: vcStatusProcessor.CreateVCStatus(strconv.Itoa(statusBitIndex), cslURL, statustype.StatusPurposeRevocation),
		Context: vcStatusProcessor.GetVCContext(),
	}

	// Store VC status to DB
	err = s.vcStatusStore.Put(ctx, profile.ID, profile.Version, credentialID, statusListEntry.TypedID)
	if err != nil {
		return nil, fmt.Errorf("failed to store credential status: %w", err)
	}

	return statusListEntry, nil
}

func (s *Manager) getProfileCSLAndAssignedIndex(ctx context.Context,
	profile *profileapi.Issuer) (string, int, error) {
	logger.Debugc(ctx, "CSL Manager - CreateCSLEntry",
		logfields.WithProfileID(profile.ID), logfields.WithProfileVersion(profile.Version))

	s.mutex.Lock()
	defer s.mutex.Unlock()

	indexWrapper, err := s.getCSLIndexWrapper(ctx, profile)
	if err != nil {
		return "", 0, fmt.Errorf("failed to get CSL Index Wrapper from store(s): %w", err)
	}

	unusedStatusBitIndex, err := s.getUnusedIndex(indexWrapper.UsedIndexes)
	if err != nil {
		return "", 0, fmt.Errorf("getUnusedIndex failed: %w", err)
	}

	// append unusedStatusBitIndex to the cslWrapper.UsedIndexes so marking it as "used".
	indexWrapper.UsedIndexes = append(indexWrapper.UsedIndexes, unusedStatusBitIndex)

	// TODO: Remove
	logger.Debugc(ctx, "updating CSL Index Wrapper for URL", log.WithURL(indexWrapper.CSLURL))

	if err = s.updateCSLIndexWrapper(ctx, indexWrapper, profile); err != nil {
		return "", 0, fmt.Errorf("failed to store CSL Index Wrapper: %w", err)
	}

	return indexWrapper.CSLURL, unusedStatusBitIndex, nil
}

func (s *Manager) getCSLIndexWrapper(ctx context.Context,
	profile *profileapi.Issuer) (*credentialstatus.CSLIndexWrapper, error) {
	// get latest ListID - global value
	latestListID, err := s.cslIndexStore.GetLatestListID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	cslURL, err := s.cslVCStore.GetCSLURL(s.externalURL, profile.GroupID, latestListID)
	if err != nil {
		return nil, fmt.Errorf("failed to createCSLIndexWrapper CSL wrapper URL: %w", err)
	}

	indexWrapper, err := s.cslIndexStore.Get(ctx, cslURL)
	if err != nil {
		if errors.Is(err, credentialstatus.ErrDataNotFound) {
			indexWrapper, err = s.createNewVCAndCSLIndexWrapper(ctx, profile, latestListID)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("failed to get CSL Index from store: %w", err)
		}
	}

	return indexWrapper, nil
}

func (s *Manager) updateCSLIndexWrapper(ctx context.Context,
	wrapper *credentialstatus.CSLIndexWrapper,
	profile *profileapi.Issuer) error {
	// TODO: Remove
	logger.Debugc(ctx, "updating CSL VC with URL", log.WithURL(wrapper.CSLURL))

	err := s.cslIndexStore.Upsert(ctx, wrapper.CSLURL, wrapper)
	if err != nil {
		return fmt.Errorf("failed to store CSL Index Wrapper: %w", err)
	}

	// If amount of used indexes is the same as list size - createCSLIndexWrapper new CSL (ListID, VC and Index Wrapper).
	// TODO: We should have used indexes > some percent of list size (e.g. 75-90%) in order to avoid collisions.
	if len(wrapper.UsedIndexes) == s.listSize {
		logger.Debugc(ctx, "reached size limit for CSL, creating new CSL ...")
		_, createErr := s.createCSLIndexWrapper(ctx, profile)
		if createErr != nil {
			return fmt.Errorf("failed to createCSLIndexWrapper new CSL: %w", createErr)
		}
	}

	return nil
}

func (s *Manager) createCSLIndexWrapper(ctx context.Context,
	profile *profileapi.Issuer) (*credentialstatus.CSLIndexWrapper, error) {
	newListID := credentialstatus.ListID(uuid.NewString())

	if err := s.cslIndexStore.UpdateLatestListID(ctx, newListID); err != nil {
		return nil, fmt.Errorf("failed to store new list ID: %w", err)
	}

	wrapper, err := s.createNewVCAndCSLIndexWrapper(ctx, profile, newListID)
	if err != nil {
		return nil, fmt.Errorf("failed to store CSL Index Wrapper: %w", err)
	}

	return wrapper, nil
}

func (s *Manager) createNewVCAndCSLIndexWrapper(ctx context.Context,
	profile *profileapi.Issuer,
	listID credentialstatus.ListID,
) (*credentialstatus.CSLIndexWrapper, error) {
	kms, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS: %w", err)
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
		SDJWT:                   vc.SDJWT{Enable: false},
	}

	cslURL, err := s.cslVCStore.GetCSLURL(s.externalURL, profile.GroupID, listID)
	if err != nil {
		return nil, fmt.Errorf("failed to createCSLIndexWrapper CSL URL: %w", err)
	}

	logger.Debugc(ctx, "creating new CSL VC with URL", log.WithURL(cslURL))

	err = s.createAndStoreVC(ctx, signer, cslURL)
	if err != nil {
		return nil, err
	}

	indexWrapper := &credentialstatus.CSLIndexWrapper{
		UsedIndexes: nil,
		CSLURL:      cslURL,
	}

	if err = s.cslIndexStore.Upsert(ctx, cslURL, indexWrapper); err != nil {
		return nil, fmt.Errorf("failed to store CSL Index Wrapper: %w", err)
	}

	return indexWrapper, nil
}

func (s *Manager) createAndStoreVC(ctx context.Context, signer *vc.Signer, cslURL string) error {
	processor, err := statustype.GetVCStatusProcessor(signer.VCStatusListType)
	if err != nil {
		return fmt.Errorf("failed to get VC status processor: %w", err)
	}

	vc, err := processor.CreateVC(cslURL, s.listSize, signer)
	if err != nil {
		return fmt.Errorf("failed to createCSLIndexWrapper VC: %w", err)
	}

	signed, err := s.crypto.SignCredential(signer, vc)
	if err != nil {
		return fmt.Errorf("failed to sign VC: %w", err)
	}

	vcBytes, err := signed.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal VC: %w", err)
	}

	vcWrapper := &credentialstatus.CSLVCWrapper{
		VCByte: vcBytes,
		VC:     vc,
	}

	if err := s.cslVCStore.Upsert(ctx, cslURL, vcWrapper); err != nil {
		return fmt.Errorf("failed to store VC: %w", err)
	}

	return nil
}

func (s *Manager) getUnusedIndex(usedIndexes []int) (int, error) {
	usedIndexesMap := make(map[int]struct{}, len(usedIndexes))

	for _, i := range usedIndexes {
		usedIndexesMap[i] = struct{}{}
	}

	unusedIndexes := make([]int, 0, s.listSize-len(usedIndexes))
	for i := 0; i < s.listSize; i++ {
		if _, ok := usedIndexesMap[i]; ok {
			continue
		}

		unusedIndexes = append(unusedIndexes, i)
	}

	if len(unusedIndexes) == 0 {
		return -1, errors.New("no possible unused indexes")
	}

	unusedIndexPosition := rand.Intn(len(unusedIndexes)) // nolint:gosec

	return unusedIndexes[unusedIndexPosition], nil
}
