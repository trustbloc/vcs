/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"
)

const signatureHashAlgorithm = "https://github.com/trustbloc/edge-service/zcapld/DIDSecrets"

func NewHTTPSigner(verMethod, zcap string, secrets httpsignatures.Secrets,
	algorithm httpsignatures.SignatureHashAlgorithm) func(*http.Request) (*http.Header, error) {
	return func(r *http.Request) (*http.Header, error) {
		hs := httpsignatures.NewHTTPSignatures(secrets)

		hs.SetSignatureHashAlgorithm(algorithm)

		r.Header.Set(
			zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, zcap, "read"),
		)

		err := hs.Sign(verMethod, r)
		if err != nil {
			return nil, fmt.Errorf("failed to sign request: %w", err)
		}

		return &r.Header, nil
	}
}

// DIDSecrets only supports DID URLs as key IDs.
type DIDSecrets struct {
	Secrets map[string]httpsignatures.Secrets
}

// Get resolves the DID URL into a secret.
func (c *DIDSecrets) Get(didURL string) (httpsignatures.Secret, error) {
	id, _, err := parseDIDURL(didURL)
	if err != nil {
		return httpsignatures.Secret{}, fmt.Errorf("failed to parse [%s]: %w", didURL, err)
	}

	secrets, supported := c.Secrets[id.Method]
	if !supported {
		return httpsignatures.Secret{}, fmt.Errorf("unsupported DID method: %s", id.Method)
	}

	secret, err := secrets.Get(didURL)
	if err != nil {
		return httpsignatures.Secret{}, fmt.Errorf("failed to fetch secret for method [%s]: %w", id.Method, err)
	}

	secret.Algorithm = signatureHashAlgorithm

	return secret, nil
}

// DIDSignatureHashAlgorithms
type DIDSignatureHashAlgorithms struct {
	KMS       KMS
	Crypto    Crypto
	Resolvers []DIDResolver
}

// Algorithm
func (a *DIDSignatureHashAlgorithms) Algorithm() string {
	return signatureHashAlgorithm
}

// Create a signature over data with the secret.
func (a *DIDSignatureHashAlgorithms) Create(secret httpsignatures.Secret, data []byte) ([]byte, error) {
	verificationMethod, err := a.derefVerMethod(secret.KeyID, did.CapabilityDelegation)
	if err != nil {
		return nil, fmt.Errorf("failed to dereference verificationMethod from didURL %s: %w", secret.KeyID, err)
	}

	keyType, err := kmsKeyType(verificationMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to map verificationMethod to a KMS keyType: %w", err)
	}

	// TODO we shouldn't be using a `localkms` function: https://github.com/trustbloc/edge-core/issues/109.
	kid, err := localkms.CreateKID(verificationMethod.Value, keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to create KID from didURL %s: %w", secret.KeyID, err)
	}

	kh, err := a.KMS.Get(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get key handle for kid %s: %w", kid, err)
	}

	sig, err := a.Crypto.Sign(data, kh)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return sig, nil
}

// Verify the signature over data using the secret.
func (a *DIDSignatureHashAlgorithms) Verify(secret httpsignatures.Secret, data []byte, signature []byte) error {
	verificationMethod, err := a.derefVerMethod(secret.KeyID, did.CapabilityDelegation)
	if err != nil {
		return fmt.Errorf("failed to dereference verificationMethod from didURL %s: %w", secret.KeyID, err)
	}

	keyType, err := kmsKeyType(verificationMethod)
	if err != nil {
		return fmt.Errorf("failed to map verificationMethod to a KMS keyType: %w", err)
	}

	kh, err := a.KMS.PubKeyBytesToHandle(verificationMethod.Value, keyType)
	if err != nil {
		return fmt.Errorf("failed to convert didURL %s pubkey to aries kms handle: %w", secret.KeyID, err)
	}

	err = a.Crypto.Verify(signature, data, kh)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	return nil
}

func (a *DIDSignatureHashAlgorithms) derefVerMethod(didURL string, rel did.VerificationRelationship) (*did.VerificationMethod, error) {
	id, fragment, err := parseDIDURL(didURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DID URL: %w", err)
	}

	var resolver DIDResolver

	for _, r := range a.Resolvers {
		if r.Accept(id.Method) {
			resolver = r

			break
		}
	}

	if resolver == nil {
		return nil, fmt.Errorf("no resolver configured for method [%s]", id.Method)
	}

	// TODO resolve options
	resolution, err := resolver.Read(id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve [%s]: %w", id.String(), err)
	}

	for _, vm := range resolution.DIDDocument.VerificationMethods(rel)[rel] {
		if fragment == vm.VerificationMethod.ID || didURL == vm.VerificationMethod.ID {
			return &vm.VerificationMethod, nil
		}
	}

	return nil, fmt.Errorf(
		"unable to dereference [%s] to a verificationMethod in DID [%s] with relation [%d]",
		didURL, id.String(), rel,
	)
}

func parseDIDURL(didURL string) (id *did.DID, fragment string, err error) {
	const numParts = 2

	parts := strings.Split(didURL, "#")
	if len(parts) != numParts {
		return nil, "", fmt.Errorf("not a did URL: %s", didURL)
	}

	id, err = did.Parse(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse DID [%s]: %w", parts[0], err)
	}

	return id, fragment, nil
}

func kmsKeyType(verMethod *did.VerificationMethod) (kms.KeyType, error) {
	supportedTypes := map[string]func(*did.VerificationMethod) (kms.KeyType, error){
		"Ed25519VerificationKey2018": func(method *did.VerificationMethod) (kms.KeyType, error) {
			return kms.ED25519, nil
		},
		"JsonWebKey2020": func(method *did.VerificationMethod) (kms.KeyType, error) {
			return supportedJWKCurves(method.JSONWebKey())
		},
	}

	keyType, supported := supportedTypes[verMethod.Type]
	if !supported {
		return "", fmt.Errorf("unsupported verificationMethod type: %s", verMethod.Type)
	}

	return keyType(verMethod)
}

func supportedJWKCurves(jwk *jose.JWK) (kms.KeyType, error) {
	curves := map[string]kms.KeyType{
		"P-256":   kms.ECDSAP256TypeDER,
		"P-384":   kms.ECDSAP384TypeDER,
		"P-521":   kms.ECDSAP521TypeDER,
		"Ed25519": kms.ED25519Type,
	}

	keyType, supported := curves[jwk.Crv]
	if !supported {
		return "", fmt.Errorf("unsupported JsonWebKey2020 crv: %s", jwk.Crv)
	}

	return keyType, nil
}
