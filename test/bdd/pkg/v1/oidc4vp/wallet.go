/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"fmt"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
)

func (e *Steps) createWallet(numOfDIDs int) error {
	var err error
	e.walletRunner, err = walletrunner.New(vcprovider.ProviderVCS, func(c *vcprovider.Config) {
		c.WalletDidCount = numOfDIDs
		c.DidMethod = "ion"
	})
	if err != nil {
		return fmt.Errorf("walletrunner.New: %w", err)
	}

	err = e.walletRunner.CreateWallet()
	if err != nil {
		return fmt.Errorf("walletRunner.CreateWallet: %w", err)
	}

	e.bddContext.CredentialSubject = append(e.bddContext.CredentialSubject, e.walletRunner.GetConfig().WalletParams.DidID...)
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
