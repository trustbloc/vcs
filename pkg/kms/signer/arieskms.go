/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"strings"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
)

type KMSSigner struct {
	keyHandle     interface{}
	crypto        crypto
	signatureType vcsverifiable.SignatureType
	bbs           bool
}

type keyManager interface {
	Get(keyID string) (interface{}, error)
}

type crypto interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
	SignMulti(messages [][]byte, kh interface{}) ([]byte, error)
}

func NewKMSSigner(keyManager keyManager, c crypto, creator string,
	signatureType vcsverifiable.SignatureType) (*KMSSigner, error) {
	// creator will contain didID#keyID
	keyID, err := diddoc.GetKeyIDFromVerificationMethod(creator)
	if err != nil {
		return nil, err
	}

	keyHandler, err := keyManager.Get(keyID)
	if err != nil {
		return nil, err
	}

	return &KMSSigner{keyHandle: keyHandler, crypto: c,
		signatureType: signatureType,
		bbs:           signatureType == vcsverifiable.BbsBlsSignature2020}, nil
}

func (s *KMSSigner) Sign(data []byte) ([]byte, error) {
	if s.bbs {
		return s.crypto.SignMulti(s.textToLines(string(data)), s.keyHandle)
	}

	v, err := s.crypto.Sign(data, s.keyHandle)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func (s *KMSSigner) Alg() string {
	return s.signatureType.Name()
}

func (s *KMSSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}
