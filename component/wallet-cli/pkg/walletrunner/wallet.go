/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/vdrutil"
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

	services, err := s.createAgentServices(s.vcProviderConf.TLS)
	if err != nil {
		return fmt.Errorf("Wallet services setup failed: %w", err)
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

	token, err := s.wallet.Open(wallet.WithUnlockByPassphrase(s.vcProviderConf.WalletParams.Passphrase))
	if err != nil {
		return fmt.Errorf("unlock wallet: %w", err)
	}

	s.vcProviderConf.WalletParams.Token = token

	vdrService, err := orb.New(nil,
		orb.WithDomain(s.vcProviderConf.DidDomain),
		orb.WithTLSConfig(s.vcProviderConf.TLS),
		orb.WithAuthToken(s.vcProviderConf.DidServiceAuthToken))
	if err != nil {
		return err
	}

	lf, err := longform.New()
	if err != nil {
		return err
	}

	vdrRegistry := vdrapi.New(vdrapi.WithVDR(vdrService), vdrapi.WithVDR(key.New()), vdrapi.WithVDR(lf))

	if shouldCreateWallet {
		createRes, err := vdrutil.DefaultVdrUtil.Create(
			s.vcProviderConf.DidMethod,
			kms.KeyType(s.vcProviderConf.DidKeyType),
			vdrRegistry,
			s.ariesServices.kms,
		)
		if err != nil {
			return err
		}

		s.vcProviderConf.WalletParams.DidID = createRes.DidID
		s.vcProviderConf.WalletParams.DidKeyID = createRes.KeyID
	} else {
		s.vcProviderConf.WalletParams.DidID = s.vcProviderConf.WalletDidID
		s.vcProviderConf.WalletParams.DidKeyID = s.vcProviderConf.WalletDidKeyID
	}

	for i := 1; i <= vdrResolveMaxRetry; i++ {
		_, err = vdrRegistry.Resolve(s.vcProviderConf.WalletParams.DidID)
		if err == nil {
			break
		}

		time.Sleep(1 * time.Second)
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

func newWallet(shouldCreate bool, userID string, passphrase string, services *ariesServices) (*wallet.Wallet, error) {
	if shouldCreate {
		err := wallet.CreateProfile(userID, services, wallet.WithPassphrase(passphrase))
		if err != nil {
			return nil, fmt.Errorf("user profile create failed: %w", err)
		}
	}

	w, err := wallet.New(userID, services)
	if err != nil {
		return nil, fmt.Errorf("create wallet failed: %w", err)
	}

	return w, nil
}

func (s *Service) SaveCredentialInWallet(vc []byte) error {
	err := s.wallet.Add(s.vcProviderConf.WalletParams.Token, wallet.Credential, vc)
	if err != nil {
		return fmt.Errorf("wallet add credential failed: %w", err)
	}

	return nil
}
