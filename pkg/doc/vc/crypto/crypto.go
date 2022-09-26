/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	ariessigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
)

const (
	// Ed25519Signature2018 ed25519 signature suite.
	Ed25519Signature2018 = "Ed25519Signature2018"
	// Ed25519Signature2020 ed25519 signature suite.
	Ed25519Signature2020 = "Ed25519Signature2020"
	// JSONWebSignature2020 json web signature suite.
	JSONWebSignature2020 = "JsonWebSignature2020"
	// BbsBlsSignature2020 signature suite.
	BbsBlsSignature2020 = "BbsBlsSignature2020"
	// EcdsaSecp256k1Signature2019 signature suite.
	EcdsaSecp256k1Signature2019 = "EcdsaSecp256k1Signature2019"

	// Ed25519VerificationKey2018 ed25119 verification key.
	Ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	// Ed25519VerificationKey2020 ed25119 verification key.
	Ed25519VerificationKey2020 = "Ed25519VerificationKey2020"
	// JSONWebKey2020 type.
	JSONWebKey2020 = "JsonWebKey2020"

	// EcdsaSecp256k1VerificationKey2019 type.
	EcdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019"

	// Bls12381G1Key2020 type.
	Bls12381G1Key2020 = "Bls12381G1Key2020"
)

const (
	// Ed25519KeyType ed25519 key type.
	Ed25519KeyType = "Ed25519"

	// P256KeyType EC P-256 key type.
	P256KeyType = "P256"
)

const (
	// AssertionMethod assertionMethod.
	AssertionMethod = "assertionMethod"

	// Authentication authentication.
	Authentication = "authentication"

	// CapabilityDelegation capabilityDelegation.
	CapabilityDelegation = "capabilityDelegation"

	// CapabilityInvocation capabilityInvocation.
	CapabilityInvocation = "capabilityInvocation"
)

const (
	// Purpose is the key of verifiable.Proof.
	Purpose = "proofPurpose"

	// VerificationMethod is the key of verifiable.Proof.
	VerificationMethod = "verificationMethod"
)

type keyManager interface {
	NewVCSigner(creator string, signatureType vc.SignatureType) (vc.SignerAlgorithm, error)
}

// New return new instance of vc crypto.
func New(vdr vdrapi.Registry, loader ld.DocumentLoader) *Crypto {
	return &Crypto{vdr: vdr, documentLoader: loader}
}

// signingOpts holds options for the signing credential.
type signingOpts struct {
	VerificationMethod string
	Purpose            string
	Representation     string
	SignatureType      vc.SignatureType
	Created            *time.Time
	Challenge          string
	Domain             string
}

// SigningOpts is signing credential option.
type SigningOpts func(opts *signingOpts)

// WithVerificationMethod is an option to pass verification method for signing.
func WithVerificationMethod(verificationMethod string) SigningOpts {
	return func(opts *signingOpts) {
		opts.VerificationMethod = verificationMethod
	}
}

// WithPurpose is an option to pass proof purpose option for signing.
func WithPurpose(purpose string) SigningOpts {
	return func(opts *signingOpts) {
		opts.Purpose = purpose
	}
}

// WithSigningRepresentation is an option to pass representation for signing.
func WithSigningRepresentation(representation string) SigningOpts {
	return func(opts *signingOpts) {
		opts.Representation = representation
	}
}

// WithSignatureType is an option to pass signature type for signing.
func WithSignatureType(signatureType vc.SignatureType) SigningOpts {
	return func(opts *signingOpts) {
		opts.SignatureType = signatureType
	}
}

// WithCreated is an option to pass created time option for signing.
func WithCreated(created *time.Time) SigningOpts {
	return func(opts *signingOpts) {
		opts.Created = created
	}
}

// WithChallenge proof challenge.
func WithChallenge(challenge string) SigningOpts {
	return func(opts *signingOpts) {
		opts.Challenge = challenge
	}
}

// WithDomain proof domain.
func WithDomain(domain string) SigningOpts {
	return func(opts *signingOpts) {
		opts.Domain = domain
	}
}

// Crypto to sign credential.
type Crypto struct {
	vdr            vdrapi.Registry
	documentLoader ld.DocumentLoader
}

// SignCredential signs vc.
func (c *Crypto) SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
	opts ...SigningOpts) (*verifiable.Credential, error) {
	signOpts := &signingOpts{}
	// apply opts
	for _, opt := range opts {
		opt(signOpts)
	}

	signatureType := signerData.SignatureType
	if signOpts.SignatureType != "" {
		signatureType = signOpts.SignatureType
	}

	signingCtx, err := c.getLinkedDataProofContext(signerData.Creator, signerData.KMS, signatureType, AssertionMethod,
		signerData.SignatureRepresentation, signOpts)
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(signingCtx, jsonld.WithDocumentLoader(c.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vc, nil
}

// SignPresentation signs a presentation.
func (c *Crypto) SignPresentation(signerData *vc.Signer, vp *verifiable.Presentation,
	opts ...SigningOpts) (*verifiable.Presentation, error) {
	signOpts := &signingOpts{}
	// apply opts
	for _, opt := range opts {
		opt(signOpts)
	}

	signatureType := signerData.SignatureType
	if signOpts.SignatureType != "" {
		signatureType = signOpts.SignatureType
	}

	signingCtx, err := c.getLinkedDataProofContext(
		signerData.Creator, signerData.KMS, signatureType, Authentication, signerData.SignatureRepresentation, signOpts)
	if err != nil {
		return nil, err
	}

	if signingCtx.Purpose == "" {
		signingCtx.Purpose = Authentication
	}

	err = vp.AddLinkedDataProof(signingCtx, jsonld.WithDocumentLoader(c.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vp, nil
}

func (c *Crypto) getLinkedDataProofContext(creator string, km keyManager,
	signatureType vc.SignatureType, proofPurpose string,
	signRep verifiable.SignatureRepresentation, opts *signingOpts) (*verifiable.LinkedDataProofContext, error) {
	s, method, err := c.getSigner(creator, km, opts, signatureType)
	if err != nil {
		return nil, err
	}

	if opts.Purpose != "" {
		proofPurpose = opts.Purpose
	}

	didDoc, err := diddoc.GetDIDDocFromVerificationMethod(method, c.vdr)
	if err != nil {
		return nil, err
	}

	err = ValidateProofPurpose(proofPurpose, method, didDoc)
	if err != nil {
		return nil, err
	}

	var signatureSuite ariessigner.SignatureSuite

	switch signatureType { //nolint: exhaustive
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(suite.WithSigner(s))
	case Ed25519Signature2020:
		signatureSuite = ed25519signature2020.New(suite.WithSigner(s))
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(s))
	case BbsBlsSignature2020:
		signatureSuite = bbsblssignature2020.New(suite.WithSigner(s))
	case EcdsaSecp256k1Signature2019:
		signatureSuite = ecdsasecp256k1signature2019.New(suite.WithSigner(s))
	default:
		return nil, fmt.Errorf("signature type unsupported %s", signatureType)
	}

	if opts.Representation != "" {
		signRep, err = getSignatureRepresentation(opts.Representation)
		if err != nil {
			return nil, err
		}
	}

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      method,
		SignatureRepresentation: signRep,
		SignatureType:           signatureType.Name(),
		Suite:                   signatureSuite,
		Purpose:                 opts.Purpose,
		Created:                 opts.Created,
		Challenge:               opts.Challenge,
		Domain:                  opts.Domain,
	}

	return signingCtx, nil
}

// getSigner returns signer and verification method based on profile and signing opts
// verificationMethod from opts takes priority to create signer and verification method.
func (c *Crypto) getSigner(creator string, km keyManager, opts *signingOpts,
	signatureType vc.SignatureType) (vc.SignerAlgorithm, string, error) {
	verificationMethod := creator
	if opts.VerificationMethod != "" {
		verificationMethod = opts.VerificationMethod
	}

	s, err := km.NewVCSigner(verificationMethod, signatureType)

	return s, verificationMethod, err
}

// ValidateProofPurpose validates the proof purpose.
func ValidateProofPurpose(proofPurpose, method string, didDoc *did.Doc) error {
	// TODO https://github.com/trustbloc/vcs/issues/368 remove check once did:sov returns both
	//  assertionMethod and authentication
	if strings.Contains(method, "did:sov") {
		return nil
	}

	var vmMatched bool

	switch proofPurpose {
	case AssertionMethod:
		assertionMethods := didDoc.VerificationMethods(did.AssertionMethod)[did.AssertionMethod]

		vmMatched = isValidVerificationMethod(method, assertionMethods)
	case Authentication:
		authMethods := didDoc.VerificationMethods(did.Authentication)[did.Authentication]

		vmMatched = isValidVerificationMethod(method, authMethods)
	case CapabilityDelegation:
		capabilityDelegationMethods := didDoc.VerificationMethods(did.CapabilityDelegation)[did.CapabilityDelegation]

		vmMatched = isValidVerificationMethod(method, capabilityDelegationMethods)
	case CapabilityInvocation:
		capabilityInvocationMethods := didDoc.VerificationMethods(did.CapabilityInvocation)[did.CapabilityInvocation]

		vmMatched = isValidVerificationMethod(method, capabilityInvocationMethods)
	default:
		return fmt.Errorf("proof purpose %s not supported", proofPurpose)
	}

	if !vmMatched {
		return fmt.Errorf("unable to find matching %s key IDs for given verification method %s",
			proofPurpose, method)
	}

	return nil
}

func isValidVerificationMethod(method string, vms []did.Verification) bool {
	for _, vm := range vms {
		if method == vm.VerificationMethod.ID {
			return true
		}
	}

	return false
}

// getSignatureRepresentation returns signing repsentation for given representation key.
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
