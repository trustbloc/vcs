/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
)

const (
	// Challenge is the key of verifiable.Proof.
	Challenge = "challenge"

	// Domain is the key of verifiable.Proof.
	Domain = "domain"
)

// GetVerificationMethodFromProof returns verification method from proof.
func GetVerificationMethodFromProof(proof verifiable.Proof) (string, error) {
	verificationMethodVal, ok := proof[VerificationMethod]
	if !ok {
		return "", errors.New("proof doesn't have verification method")
	}

	method, ok := verificationMethodVal.(string)
	if !ok {
		return "", errors.New("proof verification method is not a string")
	}

	return method, nil
}

// ValidateProof validates proof.
func ValidateProof(proof verifiable.Proof, verificationMethod string, didDoc *did.Doc) error {
	purposeVal, ok := proof[Purpose]
	if !ok {
		return errors.New("proof doesn't have purpose")
	}

	purpose, ok := purposeVal.(string)
	if !ok {
		return errors.New("proof purpose is not a string")
	}

	return ValidateProofPurpose(purpose, verificationMethod, didDoc)
}

// ValidateProofKey checks whether the key equals to expectedValue in a given proof.
func ValidateProofKey(proof verifiable.Proof, key, expectedValue string) error {
	actualVal := ""

	val, ok := proof[key]
	if ok {
		actualVal, _ = val.(string) // nolint
	}

	if expectedValue != actualVal {
		return fmt.Errorf("invalid %s in the proof : expected=%s actual=%s", key, expectedValue, actualVal)
	}

	return nil
}
