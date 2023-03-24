/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import "encoding/json"

func (s *Service) EncryptClaims(data map[string]interface{}) (*ClaimData, error) {
	bytesData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	encrypted, nonce, err := s.crypto.Encrypt(bytesData, nil, s.cryptoKeyID)
	if err != nil {
		return nil, err
	}

	return &ClaimData{
		Encrypted:      encrypted,
		EncryptedNonce: nonce,
	}, nil
}

func (s *Service) DecryptClaims(data *ClaimData) (map[string]interface{}, error) {
	resp, err := s.crypto.Decrypt(nil, data.Encrypted, data.EncryptedNonce, s.cryptoKeyID)
	if err != nil {
		return nil, err
	}

	finalMap := map[string]interface{}{}
	if err = json.Unmarshal(resp, &finalMap); err != nil {
		return nil, err
	}

	return finalMap, nil
}
