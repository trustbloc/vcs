/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"fmt"
	"time"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
)

func (e *Steps) createWallet(numOfDIDs int) error {
	var err error
	if e.walletRunner != nil {
		if wallet := e.walletRunner.GetWallet(); wallet != nil {
			_ = wallet.Close()
		}
	}

	e.walletRunner = nil
	e.walletRunner, err = walletrunner.New(vcprovider.ProviderVCS, func(c *vcprovider.Config) {
		c.WalletDidCount = numOfDIDs
		c.DidMethod = "orb"
	})

	if err != nil {
		e.walletRunner = nil
		return fmt.Errorf("walletrunner.New: %w", err)
	}

	err = e.walletRunner.CreateWallet()
	if err != nil {
		e.walletRunner = nil
		return fmt.Errorf("walletRunner.CreateWallet: %w", err)
	}

	time.Sleep(1 * time.Second)
	e.bddContext.CredentialSubject = append(e.bddContext.CredentialSubject,
		e.walletRunner.GetConfig().WalletParams.DidID...)

	return nil
}
func (e *Steps) saveCredentialsInWallet() error {
	for _, cred := range e.bddContext.CreatedCredentialsSet {
		err := e.walletRunner.SaveCredentialInWallet(cred)
		if err != nil {
			return fmt.Errorf("wallet add credential failed: %w", err)
		}
	}

	return nil
}
