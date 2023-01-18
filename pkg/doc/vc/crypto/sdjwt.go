/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto"
	"fmt"

	afjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	afjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/issuer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

type CredentialSubjectDigests struct {
	Subject     interface{}
	Disclosures []string
}

// getSDJWTCredentialSubjectDigests returns credentialSubjectDigests
// based on credential subject claims.
func (c *Crypto) getSDJWTCredentialSubjectDigests(
	credential *verifiable.Credential, hashAlgo crypto.Hash) (*CredentialSubjectDigests, error) {
	claims, err := credential.JWTClaims(false)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT claims: %w", err)
	}

	subject := claims.VC["credentialSubject"]
	switch t := subject.(type) {
	case string:
		// Not possible to create SD-JWT digests for SUbject as a string.
		return &CredentialSubjectDigests{
			Subject:     credential.Subject,
			Disclosures: []string{},
		}, nil
	case map[string]interface{}:
		delete(t, "id")
	}

	sdJWTToken, err := issuer.New(
		claims.Issuer,
		subject,
		nil,
		&unsecuredJWTSigner{},
		issuer.WithHashAlgorithm(hashAlgo),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SD-JWT token: %w", err)
	}

	return &CredentialSubjectDigests{
		Subject: verifiable.Subject{
			ID: claims.Subject,
			CustomFields: map[string]interface{}{
				common.SDKey:          sdJWTToken.SignedJWT.Payload[common.SDKey],
				common.SDAlgorithmKey: sdJWTToken.SignedJWT.Payload[common.SDAlgorithmKey],
			},
		},
		Disclosures: sdJWTToken.Disclosures,
	}, nil
}

type unsecuredJWTSigner struct{}

func (s unsecuredJWTSigner) Sign(_ []byte) ([]byte, error) {
	return []byte(""), nil
}

func (s unsecuredJWTSigner) Headers() afjose.Headers {
	return map[string]interface{}{
		afjose.HeaderAlgorithm: afjwt.AlgorithmNone,
	}
}
