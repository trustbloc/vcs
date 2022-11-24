/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

type OIDC4CIConfig struct {
	InitiateIssuanceURL string
	ClientID            string
}

func (s *Service) RunOIDC4CI(config *OIDC4CIConfig) error {
	return nil
}
