/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
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

type signer struct {
	kms   legacykms.KMS
	keyID string
}

func newSigner(kms legacykms.KMS, keyID string) *signer {
	return &signer{kms: kms, keyID: keyID}
}

func (s *signer) Sign(data []byte) ([]byte, error) {
	return s.kms.SignMessage(data, s.keyID)
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
	// creator will contain didID#keyID
	idSplit := strings.Split(dataProfile.Creator, "#")
	if len(idSplit) != creatorParts {
		return nil, fmt.Errorf("wrong id %s to resolve", idSplit)
	}

	// idSplit[0] is didID
	// idSplit[1] is keyID
	key, err := c.fetchPublicKey(idSplit[0], "#"+idSplit[1])
	if err != nil {
		return nil, err
	}

	signingCtx := &verifiable.LinkedDataProofContext{
		Creator:       dataProfile.Creator,
		SignatureType: dataProfile.SignatureType,
		Suite:         ed25519signature2018.New(ed25519signature2018.WithSigner(newSigner(c.kms, base58.Encode(key)))),
	}

	err = vc.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vc, nil
}

func (c *Crypto) fetchPublicKey(didID, keyID string) ([]byte, error) {
	k, err := c.kResolver.PublicKeyFetcher()(didID, keyID)
	if err != nil {
		return nil, err
	}

	key, ok := k.([]byte)
	if !ok {
		return nil, fmt.Errorf("public key not bytes")
	}

	return key, nil
}
