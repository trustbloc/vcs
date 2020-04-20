/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	ariessigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"

	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
)

const (
	creatorParts = 2
)

const (
	// Ed25519Signature2018 ed25519 signature suite
	Ed25519Signature2018 = "Ed25519Signature2018"
	// JSONWebSignature2020 json web signature suite
	JSONWebSignature2020 = "JsonWebSignature2020"

	// Ed25519VerificationKey2018 ed25119 verification key
	Ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	// JwsVerificationKey2020 jws verification key
	JwsVerificationKey2020 = "JwsVerificationKey2020"
)

const (
	// Ed25519KeyType ed25519 key type
	Ed25519KeyType = "Ed25519"

	// P256KeyType EC P-256 key type
	P256KeyType = "P256"
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
	keyType    string
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

	v := k.Value

	if k.JWK != nil {
		var ok bool
		v, ok = k.JWK.Public().Key.(ed25519.PublicKey)

		if !ok {
			return nil, fmt.Errorf("public key not ed25519.PublicKey")
		}
	}

	keyID := base58.Encode(v)

	return &kmsSigner{kms: kms, keyID: keyID}, nil
}

func (s *kmsSigner) Sign(data []byte) ([]byte, error) {
	return s.kms.SignMessage(data, s.keyID)
}

func newPrivateKeySigner(keyType string, privateKey []byte) *privateKeySigner {
	return &privateKeySigner{keyType: keyType, privateKey: privateKey}
}

func (s *privateKeySigner) Sign(data []byte) ([]byte, error) {
	switch s.keyType {
	case Ed25519KeyType:
		return ed25519.Sign(s.privateKey, data), nil
	case P256KeyType:
		ecPrivateKey, err := x509.ParseECPrivateKey(s.privateKey)
		if err != nil {
			return nil, err
		}

		return signEcdsa(data, ecPrivateKey, crypto.SHA256)
	}

	return nil, fmt.Errorf("invalid key type : %s", s.keyType)
}

// New return new instance of vc crypto
func New(kms legacykms.KMS, kResolver keyResolver) *Crypto {
	return &Crypto{kms: kms, kResolver: kResolver}
}

// signingOpts holds options for the signing credential
type signingOpts struct {
	VerificationMethod string
	Purpose            string
	Representation     string
	SignatureType      string
	Created            *time.Time
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
		opts.Representation = representation
	}
}

// WithSignatureType is an option to pass signature type for signing
func WithSignatureType(signatureType string) SigningOpts {
	return func(opts *signingOpts) {
		opts.SignatureType = signatureType
	}
}

// WithCreated is an option to pass created time option for signing
func WithCreated(created *time.Time) SigningOpts {
	return func(opts *signingOpts) {
		opts.Created = created
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
	if signOpts.Representation != "" {
		repres, err = getSignatureRepresentation(signOpts.Representation)
		if err != nil {
			return nil, err
		}
	}

	signatureType := dataProfile.SignatureType
	if signOpts.SignatureType != "" {
		signatureType = signOpts.SignatureType
	}

	var signatureSuite ariessigner.SignatureSuite

	switch signatureType {
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(suite.WithSigner(s))
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(s))
	default:
		return nil, fmt.Errorf("signature type unsupported %s", signatureType)
	}

	// TODO Matching suite and type for signOpts.VerificationMethod [Issue #222]
	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      method,
		SignatureRepresentation: repres,
		SignatureType:           signatureType,
		Suite:                   signatureSuite,
		Purpose:                 signOpts.Purpose,
		Created:                 signOpts.Created,
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
		did, err := getDIDFromKeyID(opts.VerificationMethod)
		if err != nil {
			return nil, "", err
		}

		// if the verification method DID is added to profile externally, then fetch the private
		// key from profile
		if did == dataProfile.DID && dataProfile.DIDPrivateKey != "" {
			return newPrivateKeySigner(dataProfile.DIDKeyType, base58.Decode(dataProfile.DIDPrivateKey)),
				opts.VerificationMethod, nil
		}

		s, err := newKMSSigner(c.kms, c.kResolver, opts.VerificationMethod)

		return s, opts.VerificationMethod, err
	case dataProfile.DIDPrivateKey == "":
		s, err := newKMSSigner(c.kms, c.kResolver, dataProfile.Creator)
		return s, dataProfile.Creator, err
	default:
		return newPrivateKeySigner(dataProfile.DIDKeyType, base58.Decode(dataProfile.DIDPrivateKey)),
			dataProfile.Creator, nil
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

func getDIDFromKeyID(creator string) (string, error) {
	// creator will contain didID#keyID
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return "", fmt.Errorf("wrong id %s to resolve", idSplit)
	}

	return idSplit[0], nil
}

func signEcdsa(doc []byte, privateKey *ecdsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	hasher := hash.New()

	_, err := hasher.Write(doc)
	if err != nil {
		return nil, err
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, err
	}

	curveBits := privateKey.Curve.Params().BitSize

	const bitsInByte = 8
	keyBytes := curveBits / bitsInByte

	if curveBits%bitsInByte > 0 {
		keyBytes++
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...), nil
}

func copyPadded(source []byte, size int) []byte {
	dest := make([]byte, size)
	copy(dest[size-len(source):], source)

	return dest
}
