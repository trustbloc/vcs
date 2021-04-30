/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"fmt"
	"strings"
	"time"

	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariessigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/internal/common/diddoc"
)

const (
	// Ed25519Signature2018 ed25519 signature suite
	Ed25519Signature2018 = "Ed25519Signature2018"
	// JSONWebSignature2020 json web signature suite
	JSONWebSignature2020 = "JsonWebSignature2020"
	// BbsBlsSignature2020 signature suite
	BbsBlsSignature2020 = "BbsBlsSignature2020"

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

const (
	// supported proof purpose

	// AssertionMethod assertionMethod
	AssertionMethod = "assertionMethod"

	// Authentication authentication
	Authentication = "authentication"

	// CapabilityDelegation capabilityDelegation
	CapabilityDelegation = "capabilityDelegation"

	// CapabilityInvocation capabilityInvocation
	CapabilityInvocation = "capabilityInvocation"
)

type kmsSigner struct {
	keyHandle interface{}
	crypto    ariescrypto.Crypto
	bbs       bool
}

func newKMSSigner(keyManager kms.KeyManager, c ariescrypto.Crypto, creator, signatureType string) (*kmsSigner, error) {
	// creator will contain didID#keyID
	keyID, err := diddoc.GetKeyIDFromVerificationMethod(creator)
	if err != nil {
		return nil, err
	}

	keyHandler, err := keyManager.Get(keyID)
	if err != nil {
		return nil, err
	}

	return &kmsSigner{keyHandle: keyHandler, crypto: c, bbs: signatureType == BbsBlsSignature2020}, nil
}

func (s *kmsSigner) Sign(data []byte) ([]byte, error) {
	if s.bbs {
		return s.crypto.SignMulti(s.textToLines(string(data)), s.keyHandle)
	}

	v, err := s.crypto.Sign(data, s.keyHandle)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func (s *kmsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

// New return new instance of vc crypto
func New(keyManager kms.KeyManager, c ariescrypto.Crypto, vdr vdrapi.Registry) *Crypto {
	return &Crypto{keyManager: keyManager, crypto: c, vdr: vdr}
}

// signingOpts holds options for the signing credential
type signingOpts struct {
	VerificationMethod string
	Purpose            string
	Representation     string
	SignatureType      string
	Created            *time.Time
	Challenge          string
	Domain             string
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

// WithChallenge proof challenge
func WithChallenge(challenge string) SigningOpts {
	return func(opts *signingOpts) {
		opts.Challenge = challenge
	}
}

// WithDomain proof domain
func WithDomain(domain string) SigningOpts {
	return func(opts *signingOpts) {
		opts.Domain = domain
	}
}

// Crypto to sign credential
type Crypto struct {
	keyManager kms.KeyManager
	crypto     ariescrypto.Crypto
	vdr        vdrapi.Registry
}

// SignCredential sign vc
func (c *Crypto) SignCredential(dataProfile *vcprofile.DataProfile, vc *verifiable.Credential,
	opts ...SigningOpts) (*verifiable.Credential, error) {
	signOpts := &signingOpts{}
	// apply opts
	for _, opt := range opts {
		opt(signOpts)
	}

	signatureType := dataProfile.SignatureType
	if signOpts.SignatureType != "" {
		signatureType = signOpts.SignatureType
	}

	signingCtx, err := c.getLinkedDataProofContext(dataProfile.Creator, signatureType, AssertionMethod,
		dataProfile.SignatureRepresentation, signOpts)
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vc, nil
}

// SignPresentation signs a presentation
func (c *Crypto) SignPresentation(profile *vcprofile.HolderProfile, vp *verifiable.Presentation,
	opts ...SigningOpts) (*verifiable.Presentation, error) {
	signOpts := &signingOpts{}
	// apply opts
	for _, opt := range opts {
		opt(signOpts)
	}

	signatureType := profile.SignatureType
	if signOpts.SignatureType != "" {
		signatureType = signOpts.SignatureType
	}

	signingCtx, err := c.getLinkedDataProofContext(
		profile.Creator, signatureType, Authentication, profile.SignatureRepresentation, signOpts)
	if err != nil {
		return nil, err
	}

	if signingCtx.Purpose == "" {
		signingCtx.Purpose = Authentication
	}

	err = vp.AddLinkedDataProof(signingCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vp, nil
}

func (c *Crypto) getLinkedDataProofContext(creator, signatureType, proofPurpose string,
	signRep verifiable.SignatureRepresentation, opts *signingOpts) (*verifiable.LinkedDataProofContext, error) {
	s, method, err := c.getSigner(creator, opts, signatureType)
	if err != nil {
		return nil, err
	}

	if opts.Purpose != "" {
		proofPurpose = opts.Purpose
	}

	didDoc, err := c.getAndResolveDID(method)
	if err != nil {
		return nil, err
	}

	err = ValidateProofPurpose(proofPurpose, method, didDoc)
	if err != nil {
		return nil, err
	}

	var signatureSuite ariessigner.SignatureSuite

	switch signatureType {
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(suite.WithSigner(s))
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(s))
	case BbsBlsSignature2020:
		signatureSuite = bbsblssignature2020.New(suite.WithSigner(s))
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
		SignatureType:           signatureType,
		Suite:                   signatureSuite,
		Purpose:                 opts.Purpose,
		Created:                 opts.Created,
		Challenge:               opts.Challenge,
		Domain:                  opts.Domain,
	}

	return signingCtx, nil
}

func (c *Crypto) getAndResolveDID(verificationMethod string) (*did.Doc, error) {
	didID, err := diddoc.GetDIDFromVerificationMethod(verificationMethod)
	if err != nil {
		return nil, err
	}

	docResolution, err := c.vdr.Resolve(didID)
	if err != nil {
		return nil, err
	}

	return docResolution.DIDDocument, nil
}

// getSigner returns signer and verification method based on profile and signing opts
// verificationMethod from opts takes priority to create signer and verification method
func (c *Crypto) getSigner(creator string, opts *signingOpts, signatureType string) (*kmsSigner, string, error) {
	verificationMethod := creator
	if opts.VerificationMethod != "" {
		verificationMethod = opts.VerificationMethod
	}

	s, err := newKMSSigner(c.keyManager, c.crypto, verificationMethod, signatureType)

	return s, verificationMethod, err
}

// ValidateProofPurpose validates the proof purpose
func ValidateProofPurpose(proofPurpose, method string, didDoc *did.Doc) error {
	// TODO https://github.com/trustbloc/edge-service/issues/368 remove check once did:sov returns both
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
