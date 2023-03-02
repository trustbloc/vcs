/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

func (s *Steps) saveCredentialsInWallet() error {
	for _, cred := range s.bddContext.CreatedCredentialsSet {
		if err := s.walletRunner.SaveCredentialInWallet(cred); err != nil {
			return err
		}
	}

	return nil
}

func (s *Steps) createWallet() error {
	err := s.walletRunner.CreateWallet()
	if err != nil {
		return err
	}

	s.bddContext.CredentialSubject = append(s.bddContext.CredentialSubject, s.walletRunner.GetConfig().WalletParams.DidID)
	return nil
}
