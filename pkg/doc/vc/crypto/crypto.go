/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"

	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
)

const (
	creatorParts = 2
)

type keyResolver interface {
	PublicKeyFetcher() verifiable.PublicKeyFetcher
}

type signer interface {
	// Sign will sign document and return signature
	Sign(data []byte) ([]byte, error)
}

type kmsSigner struct {
	kms   legacykms.KMS
	keyID string
}

type privateKeySigner struct {
	privateKey []byte
}

func newKMSSigner(kms legacykms.KMS, kResolver keyResolver, creator string) (*kmsSigner, error) {
	// creator will contain didID#keyID
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return nil, fmt.Errorf("wrong id %s to resolve", idSplit)
	}

	k, err := kResolver.PublicKeyFetcher()(idSplit[0], "#"+idSplit[1])
	if err != nil {
		return nil, err
	}

	key, ok := k.([]byte)
	if !ok {
		return nil, fmt.Errorf("public key not bytes")
	}

	keyID := base58.Encode(key)

	return &kmsSigner{kms: kms, keyID: keyID}, nil
}

func (s *kmsSigner) Sign(data []byte) ([]byte, error) {
	return s.kms.SignMessage(data, s.keyID)
}

func newPrivateKeySigner(privateKey []byte) *privateKeySigner {
	return &privateKeySigner{privateKey: privateKey}
}

func (s *privateKeySigner) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, data), nil
}

// New return new instance of vc crypto
func New(kms legacykms.KMS, kResolver keyResolver) *Crypto {
	return &Crypto{kms: kms, kResolver: kResolver}
}

// Crypto to sign credential
type Crypto struct {
	kms       legacykms.KMS
	kResolver keyResolver
}

// SignCredential sign vc
func (c *Crypto) SignCredential(dataProfile *vcprofile.DataProfile, vc *verifiable.Credential) (*verifiable.Credential, error) { // nolint:lll
	var s signer

	s = newPrivateKeySigner(base58.Decode(dataProfile.DIDPrivateKey))

	if dataProfile.DIDPrivateKey == "" {
		var err error

		s, err = newKMSSigner(c.kms, c.kResolver, dataProfile.Creator)
		if err != nil {
			return nil, err
		}
	}

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      dataProfile.Creator,
		SignatureRepresentation: verifiable.SignatureProofValue,
		SignatureType:           dataProfile.SignatureType,
		Suite: ed25519signature2018.New(
			ed25519signature2018.WithSigner(s)),
	}

	err := vc.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vc, nil
}
