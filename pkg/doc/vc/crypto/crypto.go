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

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
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

	keyID := base58.Encode(k.Value)

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

// signingOpts holds options for the signing credential
type signingOpts struct {
	VerificationMethod string
	Purpose            string
	representation     string
}

// SigningOpts is signing credential option
type SigningOpts func(opts *signingOpts)

// WithVerificationMethod is an option to pass verification method for signing
func WithVerificationMethod(verificationMethod string) SigningOpts {
	return func(opts *signingOpts) {
		opts.VerificationMethod = verificationMethod
	}
}

// WithPurpose is an option to pass proof purpose option for signing
func WithPurpose(purpose string) SigningOpts {
	return func(opts *signingOpts) {
		opts.Purpose = purpose
	}
}

// WithSigningRepresentation is an option to pass representation for signing
func WithSigningRepresentation(representation string) SigningOpts {
	return func(opts *signingOpts) {
		opts.representation = representation
	}
}

// Crypto to sign credential
type Crypto struct {
	kms       legacykms.KMS
	kResolver keyResolver
}

// SignCredential sign vc
func (c *Crypto) SignCredential(dataProfile *vcprofile.DataProfile, vc *verifiable.Credential, opts ...SigningOpts) (*verifiable.Credential, error) { // nolint:lll
	signOpts := &signingOpts{}
	// apply opts
	for _, opt := range opts {
		opt(signOpts)
	}

	s, method, err := c.getSigner(dataProfile, signOpts)
	if err != nil {
		return nil, err
	}

	repres := dataProfile.SignatureRepresentation
	if signOpts.representation != "" {
		repres, err = getSignatureRepresentation(signOpts.representation)
		if err != nil {
			return nil, err
		}
	}

	// TODO Matching suite and type  for signOpts.VerificationMethod [Issue #222]
	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      method,
		SignatureRepresentation: repres,
		SignatureType:           dataProfile.SignatureType,
		Suite: ed25519signature2018.New(
			suite.WithSigner(s)),
		Purpose: signOpts.Purpose,
	}

	err = vc.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vc, nil
}

// getSigner returns signer and verification method based on profile and signing opts
// verificationMethod from opts takes priority to create signer and verification method
func (c *Crypto) getSigner(dataProfile *vcprofile.DataProfile, opts *signingOpts) (signer, string, error) {
	switch {
	case opts.VerificationMethod != "":
		s, err := newKMSSigner(c.kms, c.kResolver, opts.VerificationMethod)
		return s, opts.VerificationMethod, err
	case dataProfile.DIDPrivateKey == "":
		s, err := newKMSSigner(c.kms, c.kResolver, dataProfile.Creator)
		return s, dataProfile.Creator, err
	default:
		return newPrivateKeySigner(base58.Decode(dataProfile.DIDPrivateKey)), dataProfile.Creator, nil
	}
}

// getSignatureRepresentation returns signing repsentation for given representation key
func getSignatureRepresentation(signRep string) (verifiable.SignatureRepresentation, error) {
	var signatureRepresentation verifiable.SignatureRepresentation

	switch signRep {
	case "jws":
		signatureRepresentation = verifiable.SignatureJWS
	case "proofValue":
		signatureRepresentation = verifiable.SignatureProofValue
	default:
		return -1, fmt.Errorf("invalid proof format : %s", signRep)
	}

	return signatureRepresentation, nil
}
