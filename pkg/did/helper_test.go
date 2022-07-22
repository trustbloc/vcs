/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/stretchr/testify/require"

	did2 "github.com/trustbloc/vcs/pkg/did"
)

func TestVerificationMethods(t *testing.T) {
	t.Run("returns the verification methods", func(t *testing.T) {
		authentication := verMethod()
		capabilityDelegation := verMethod()

		result, err := did2.VerificationMethods(
			&did.Doc{
				Authentication:       []did.Verification{newVerification(authentication, did.Authentication)},
				CapabilityDelegation: []did.Verification{newVerification(capabilityDelegation, did.CapabilityDelegation)},
			},
			did.Authentication, did.CapabilityDelegation,
		)
		require.NoError(t, err)
		require.Equal(t, []*did.VerificationMethod{authentication, capabilityDelegation}, result)
	})

	t.Run("error if did doc does not have a given verification method relation", func(t *testing.T) {
		_, err := did2.VerificationMethods(
			&did.Doc{},
			did.Authentication,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not have a verification method for relation")
	})
}

func TestFragments(t *testing.T) {
	t.Run("returns the fragment", func(t *testing.T) {
		expected := "key-1"
		result, err := did2.Fragments("did:example:123#" + expected)
		require.NoError(t, err)
		require.Equal(t, []string{expected}, result)
	})

	t.Run("error if url does not have a fragment", func(t *testing.T) {
		_, err := did2.Fragments("did:example:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "no fragment in url")
	})
}

func verMethod() *did.VerificationMethod {
	return &did.VerificationMethod{
		ID:         uuid.New().String(),
		Type:       uuid.New().String(),
		Controller: uuid.New().String(),
		Value:      []byte(uuid.New().String()),
	}
}

func newVerification(vm *did.VerificationMethod, relation did.VerificationRelationship) did.Verification {
	return did.Verification{
		VerificationMethod: *vm,
		Relationship:       relation,
		Embedded:           true,
	}
}
