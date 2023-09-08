/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/vdrutil"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

const (
	didMethodVeres   = "v1"
	didMethodElement = "elem"
	didMethodSov     = "sov"
	didMethodWeb     = "web"
	didMethodFactom  = "factom"
	didMethodORB     = "orb"
	didMethodKey     = "key"
	didMethodION     = "ion"
)

// Wallet provides verifiable credential storing, fetching, and presentation definition querying.
type Wallet interface {
	// Open opens wallet.
	Open(passPhrase string) string
	// Close closes wallet.
	Close() bool
	// Add adds a marshalled credential to the wallet.
	Add(content json.RawMessage) error
	// GetAll returns all stored credentials.
	GetAll() (map[string]json.RawMessage, error)
	// Query runs the given presentation definition on the stored credentials.
	Query(pdBytes []byte) ([]*verifiable.Presentation, error)
}

func (s *Service) GetWallet() Wallet {
	return s.wallet
}

func (s *Service) CreateWallet() error {
	shouldCreateWallet := s.vcProviderConf.WalletUserId == ""

	if shouldCreateWallet {
		s.print("Creating wallet")
		s.vcProviderConf.WalletParams.UserID = "testUserID" + uuid.NewString()
		s.vcProviderConf.WalletParams.Passphrase = "passphrase122334"
	} else {
		s.print("Using existing wallet")
		s.vcProviderConf.WalletParams.UserID = s.vcProviderConf.WalletUserId
		s.vcProviderConf.WalletParams.Passphrase = s.vcProviderConf.WalletPassPhrase
	}

	if s.wallet == nil {
		services, err := s.createAgentServices(s.vcProviderConf)
		if err != nil {
			return fmt.Errorf("wallet services setup failed: %w", err)
		}

		s.ariesServices = services

		w, err := newWallet(
			shouldCreateWallet,
			s.vcProviderConf.WalletParams.UserID,
			s.vcProviderConf.WalletParams.Passphrase,
			s.ariesServices,
		)
		if err != nil {
			return err
		}

		s.wallet = w
	}

	var err error

	token := s.wallet.Open(s.vcProviderConf.WalletParams.Passphrase)

	if token != "" {
		s.vcProviderConf.WalletParams.Token = token
	}

	if shouldCreateWallet {
		var createRes *vdrutil.CreateResult
		for i := 0; i < s.vcProviderConf.WalletDidCount; i++ {
			createRes, err = vdrutil.DefaultVdrUtil.Create(
				s.vcProviderConf.DidMethod,
				kms.KeyType(s.vcProviderConf.DidKeyType),
				s.ariesServices.vdrRegistry,
				s.ariesServices.kms,
			)
			if err != nil {
				return err
			}

			s.vcProviderConf.WalletParams.DidID = append(s.vcProviderConf.WalletParams.DidID, createRes.DidID)
			s.vcProviderConf.WalletParams.DidKeyID = append(s.vcProviderConf.WalletParams.DidKeyID, createRes.KeyID)
		}
	} else {
		s.vcProviderConf.WalletParams.DidID = append(s.vcProviderConf.WalletParams.DidID, s.vcProviderConf.WalletDidID)
		s.vcProviderConf.WalletParams.DidKeyID = append(s.vcProviderConf.WalletParams.DidKeyID, s.vcProviderConf.WalletDidKeyID)
	}

	switch s.vcProviderConf.DidKeyType {
	case "ED25519":
		s.vcProviderConf.WalletParams.SignType = vcs.EdDSA
	case "ECDSAP256DER":
		s.vcProviderConf.WalletParams.SignType = vcs.ES256
	case "ECDSAP384DER":
		s.vcProviderConf.WalletParams.SignType = vcs.ES384
	}

	for i := 0; i < s.vcProviderConf.WalletDidCount; i++ {
		for j := 1; j <= vdrResolveMaxRetry; j++ {
			_, err = s.ariesServices.vdrRegistry.Resolve(s.vcProviderConf.WalletParams.DidID[i])
			if err == nil {
				break
			}

			time.Sleep(1 * time.Second)
		}
	}

	storageType := strings.ToLower(s.vcProviderConf.StorageProvider)
	if storageType == "" {
		storageType = "in-memory"
	}

	fmt.Printf("\tStorage: %s\n", storageType)
	fmt.Printf("\tWallet UserID: [%s]\n", s.vcProviderConf.WalletParams.UserID)
	fmt.Printf("\tWallet DID: [%s]\n", s.vcProviderConf.WalletParams.DidID)
	fmt.Printf("\tWallet DID KeyID: [%s]\n\n", s.vcProviderConf.WalletParams.DidKeyID)

	return nil
}

func newWallet(shouldCreate bool, userID string, passphrase string, services *ariesServices) (Wallet, error) {
	store, err := services.storageProvider.OpenStore("wallet:credential")
	if err != nil {
		return nil, err
	}

	return &walletImpl{
		credStore: store,
		ldLoader:  services.documentLoader,
		storeLock: sync.RWMutex{},
	}, nil
}

func (s *Service) SaveCredentialInWallet(vc []byte) error {
	err := s.wallet.Add(vc)
	if err != nil {
		return fmt.Errorf("wallet add credential failed: %w", err)
	}

	return nil
}
