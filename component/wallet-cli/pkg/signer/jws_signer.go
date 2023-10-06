/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"github.com/trustbloc/kms-go/doc/jose"

	"github.com/trustbloc/vcs/pkg/doc/vc"
)

type JWSSigner struct {
	keyID            string
	signingAlgorithm string
	signer           vc.SignerAlgorithm
}

func NewJWSSigner(keyID string, signingAlgorithm string, signer vc.SignerAlgorithm) *JWSSigner {
	return &JWSSigner{
		keyID:            keyID,
		signingAlgorithm: signingAlgorithm,
		signer:           signer,
	}
}

// Sign signs data.
func (s *JWSSigner) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

// Headers provides JWS headers.
// "alg" header must be provided (see https://tools.ietf.org/html/rfc7515#section-4.1).
func (s *JWSSigner) Headers() jose.Headers {
	return jose.Headers{
		jose.HeaderKeyID:     s.keyID,
		jose.HeaderAlgorithm: s.signingAlgorithm,
	}
}
