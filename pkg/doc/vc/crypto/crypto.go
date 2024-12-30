/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"fmt"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/doc/did"
	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/veraison/go-cose"

	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/jwtproofs/eddsa"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es256"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es256k"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es384"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es521"
	"github.com/trustbloc/vc-go/proof/jwtproofs/ps256"
	"github.com/trustbloc/vc-go/proof/jwtproofs/rs256"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignature2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/ecdsasecp256k1signature2019"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2018"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/jsonwebsignature2020"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/jws"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
)

const (
	// Ed25519VerificationKey2018 ed25119 verification type.
	Ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	// Ed25519VerificationKey2020 ed25119 verification type.
	Ed25519VerificationKey2020 = "Ed25519VerificationKey2020"
	// JSONWebKey2020 verification type.
	JSONWebKey2020 = "JsonWebKey2020"
	// EcdsaSecp256k1VerificationKey2019 verification type.
	EcdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019"
	// Bls12381G2Key2020 verification type.
	Bls12381G2Key2020 = "Bls12381G2Key2020"
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
	NewVCSigner(creator string, signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error)
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
	SignatureType      vcsverifiable.SignatureType
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
func WithSignatureType(signatureType vcsverifiable.SignatureType) SigningOpts {
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

func (c *Crypto) SignCredential(
	signerData *vc.Signer, vc *verifiable.Credential, opts ...SigningOpts) (*verifiable.Credential, error) {
	switch signerData.Format {
	case vcsverifiable.Cwt:
		return c.signCredentialCWT(signerData, vc, opts...)
	case vcsverifiable.Jwt:
		return c.signCredentialJWT(signerData, vc, opts...)
	case vcsverifiable.Ldp:
		if signerData.DataIntegrityProof.Enable {
			return c.signCredentialLDPDataIntegrity(signerData, vc, opts...)
		}

		return c.signCredentialLDP(signerData, vc, opts...)
	default:
		return nil, fmt.Errorf("unknown signature format %s", signerData.Format)
	}
}

// NewJWTSigned returns JWT signed claims.
func (c *Crypto) NewJWTSigned(claims interface{}, signerData *vc.Signer) (string, error) {
	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(signerData.KeyType)
	if err != nil {
		return "", fmt.Errorf("getting JWS algo based on signature type: %w", err)
	}

	jwtAlgoStr, err := jwsAlgo.Name()
	if err != nil {
		return "", fmt.Errorf("get jwt algo name: %w", err)
	}

	signer, _, err := c.GetSigner(signerData.KMSKeyID, signerData.KMS, signerData.SignatureType)
	if err != nil {
		return "", err
	}

	token, err := jwt.NewSigned(claims, jwt.SignParameters{
		KeyID:  signerData.Creator,
		JWTAlg: jwtAlgoStr,
	}, newProofCreator(signer))
	if err != nil {
		return "", fmt.Errorf("newSigned: %w", err)
	}

	return token.Serialize(false)
}

func newProofCreator(signer vc.SignerAlgorithm) *creator.ProofCreator {
	return creator.New(
		creator.WithJWTAlg(eddsa.New(), signer),
		creator.WithJWTAlg(es256.New(), signer),
		creator.WithJWTAlg(es256k.New(), signer),
		creator.WithJWTAlg(es384.New(), signer),
		creator.WithJWTAlg(es521.New(), signer),
		creator.WithJWTAlg(rs256.New(), signer),
		creator.WithJWTAlg(ps256.New(), signer),
		creator.WithLDProofType(bbsblssignature2020.New(), signer),
		creator.WithLDProofType(ecdsasecp256k1signature2019.New(), signer),
		creator.WithLDProofType(ed25519signature2018.New(), signer),
		creator.WithLDProofType(ed25519signature2020.New(), signer),
		creator.WithLDProofType(jsonwebsignature2020.New(), signer),
	)
}

// signCredentialLDP adds verifiable.LinkedDataProofContext to the VC.
func (c *Crypto) signCredentialLDP(
	signerData *vc.Signer, vc *verifiable.Credential, opts ...SigningOpts) (*verifiable.Credential, error) {
	signOpts := &signingOpts{}
	// apply opts
	for _, opt := range opts {
		opt(signOpts)
	}

	signatureType := signerData.SignatureType
	if signOpts.SignatureType != "" {
		signatureType = signOpts.SignatureType
	}

	if signOpts.Purpose == "" {
		signOpts.Purpose = Authentication
	}

	signingCtx, err := c.getLinkedDataProofContext(signerData, signerData.KMS, signatureType, Authentication,
		signerData.SignatureRepresentation, signOpts)
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(signingCtx, ldprocessor.WithDocumentLoader(c.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vc, nil
}

func (c *Crypto) prepareSigner(signerData *vc.Signer, opts ...SigningOpts) (vc.SignerAlgorithm, string, error) {
	signOpts := &signingOpts{}
	// apply opts
	for _, opt := range opts {
		opt(signOpts)
	}

	signatureType := signerData.SignatureType
	if signOpts.SignatureType != "" {
		signatureType = signOpts.SignatureType
	}

	s, _, err := c.GetSigner(signerData.KMSKeyID, signerData.KMS, signatureType)
	if err != nil {
		return nil, "", fmt.Errorf("getting signer for JWS: %w", err)
	}

	method := signerData.Creator

	didDoc, err := diddoc.GetDIDDocFromVerificationMethod(method, c.vdr)
	if err != nil {
		return nil, "", fmt.Errorf("unable to get did doc from verification method %w", err)
	}

	proofPurpose := Authentication
	if signOpts.Purpose != "" {
		proofPurpose = signOpts.Purpose
	}

	err = ValidateProofPurpose(proofPurpose, method, didDoc)
	if err != nil {
		return nil, "", fmt.Errorf("ValidateProofPurpose error: %w", err)
	}

	return s, method, nil
}

// signCredentialJWT returns vc in JWT format including the signature section.
func (c *Crypto) signCredentialCWT(
	signerData *vc.Signer,
	credential *verifiable.Credential,
	opts ...SigningOpts,
) (*verifiable.Credential, error) {
	s, method, err := c.prepareSigner(signerData, opts...)
	if err != nil {
		return nil, err
	}

	cwtAlgo, err := verifiable.KeyTypeToCWSAlgo(signerData.KeyType)
	if err != nil {
		return nil, fmt.Errorf("getting JWS algo based on signature type: %w", err)
	}

	return c.getCWTSignedCredential(credential, s, cwtAlgo, method)
}

// signCredentialJWT returns vc in JWT format including the signature section.
func (c *Crypto) signCredentialJWT(
	signerData *vc.Signer,
	credential *verifiable.Credential,
	opts ...SigningOpts,
) (*verifiable.Credential, error) {
	s, method, err := c.prepareSigner(signerData, opts...)
	if err != nil {
		return nil, err
	}

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(signerData.KeyType)
	if err != nil {
		return nil, fmt.Errorf("getting JWS algo based on signature type: %w", err)
	}

	if signerData.SDJWT.Enable {
		options := []verifiable.MakeSDJWTOption{
			verifiable.MakeSDJWTWithHash(signerData.SDJWT.HashAlg),
			verifiable.MakeSDJWTWithVersion(signerData.SDJWT.Version),
			verifiable.MakeSDJWTWithNonSelectivelyDisclosableClaims([]string{"id", "type", "@type"}),
		}

		return c.getSDJWTSignedCredential(credential, s, jwsAlgo, method, options...)
	}

	return c.getJWTSignedCredential(credential, s, jwsAlgo, method)
}

func (c *Crypto) getCWTSignedCredential(
	credential *verifiable.Credential,
	signer vc.SignerAlgorithm,
	cwsAlgo cose.Algorithm,
	signingKeyID string,
) (*verifiable.Credential, error) {
	var err error

	credential, err = credential.CreateSignedCOSEVC(cwsAlgo, newProofCreator(signer), signingKeyID)
	if err != nil {
		return nil, fmt.Errorf("MarshalJWS error: %w", err)
	}

	return credential, nil
}

func (c *Crypto) getJWTSignedCredential(
	credential *verifiable.Credential,
	signer vc.SignerAlgorithm,
	jwsAlgo verifiable.JWSAlgorithm,
	signingKeyID string,
) (*verifiable.Credential, error) {
	var err error

	credential, err = credential.CreateSignedJWTVC(false, jwsAlgo, newProofCreator(signer), signingKeyID)
	if err != nil {
		return nil, fmt.Errorf("MarshalJWS error: %w", err)
	}

	return credential, nil
}

func (c *Crypto) getSDJWTSignedCredential(
	credential *verifiable.Credential,
	signer vc.SignerAlgorithm,
	jwsAlgo verifiable.JWSAlgorithm,
	signingKeyID string,
	options ...verifiable.MakeSDJWTOption,
) (*verifiable.Credential, error) {
	jwsAlgName, err := jwsAlgo.Name()
	if err != nil {
		return nil, fmt.Errorf("getting JWS algo name error: %w", err)
	}

	joseSigner := jws.NewSigner(signingKeyID, jwsAlgName, signer)

	//
	sdjwt, err := credential.MakeSDJWT(joseSigner, signingKeyID, options...)
	if err != nil {
		return nil, fmt.Errorf("make SDJWT credential error: %w", err)
	}

	sdCred, err := verifiable.ParseCredential([]byte(sdjwt), verifiable.WithCredDisableValidation(),
		verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, fmt.Errorf("reparse SDJWT credential error: %w", err)
	}

	return sdCred, nil
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
		signerData, signerData.KMS, signatureType, Authentication, signerData.SignatureRepresentation, signOpts)
	if err != nil {
		return nil, err
	}

	if signingCtx.Purpose == "" {
		signingCtx.Purpose = Authentication
	}

	err = vp.AddLinkedDataProof(signingCtx, ldprocessor.WithDocumentLoader(c.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to sign vp: %w", err)
	}

	return vp, nil
}

func (c *Crypto) getLinkedDataProofContext(signerData *vc.Signer, km keyManager,
	signatureType vcsverifiable.SignatureType, proofPurpose string,
	signRep verifiable.SignatureRepresentation, opts *signingOpts) (*verifiable.LinkedDataProofContext, error) {
	s, _, err := c.GetSigner(signerData.KMSKeyID, km, signatureType)
	if err != nil {
		return nil, err
	}

	if opts.Purpose != "" {
		proofPurpose = opts.Purpose
	}

	method := signerData.Creator

	didDoc, err := diddoc.GetDIDDocFromVerificationMethod(method, c.vdr)
	if err != nil {
		return nil, err
	}

	err = ValidateProofPurpose(proofPurpose, method, didDoc)
	if err != nil {
		return nil, err
	}

	proofCreator := newProofCreator(s)

	if opts.Representation != "" {
		signRep, err = getSignatureRepresentation(opts.Representation)
		if err != nil {
			return nil, err
		}
	}

	vm := method

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      vm,
		KeyType:                 signerData.KeyType,
		SignatureRepresentation: signRep,
		SignatureType:           signatureType.Name(),
		ProofCreator:            proofCreator,
		Purpose:                 opts.Purpose,
		Created:                 opts.Created,
		Challenge:               opts.Challenge,
		Domain:                  opts.Domain,
	}

	return signingCtx, nil
}

// GetSigner returns signer and verification method based on profile and signing opts
// verificationMethod from opts takes priority to create signer and verification method.
//
//nolint:unparam
func (c *Crypto) GetSigner(
	kmsKeyID string,
	km keyManager,
	signatureType vcsverifiable.SignatureType,
) (vc.SignerAlgorithm, string, error) {
	s, err := km.NewVCSigner(kmsKeyID, signatureType)

	return s, kmsKeyID, err
}

// ValidateProofPurpose validates the proof purpose.
func ValidateProofPurpose(proofPurpose, method string, didDoc *did.Doc) error {
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
