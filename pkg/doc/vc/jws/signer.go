/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
)

type signer interface {
	Sign(data []byte) ([]byte, error)
}

type Signer struct {
	keyID        string
	jwsAlgorithm string
	signer       signer
}

func NewSigner(keyID string, jwsAlgorithm string, signer signer) *Signer {
	return &Signer{
		keyID:        keyID,
		jwsAlgorithm: jwsAlgorithm,
		signer:       signer,
	}
}

// Sign signs data.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

// Headers provides JWS headers. "alg" header must be provided (see https://tools.ietf.org/html/rfc7515#section-4.1)
func (s *Signer) Headers() jose.Headers {
	return jose.Headers{
		jose.HeaderKeyID:     s.keyID,
		jose.HeaderAlgorithm: s.jwsAlgorithm,
	}
}
