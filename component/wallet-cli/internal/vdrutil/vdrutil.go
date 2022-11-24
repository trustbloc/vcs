/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdrutil

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/kms/key"
)

type CreateResult struct {
	DidID string
	KeyID string
}

type keyManager interface {
	Get(keyID string) (interface{}, error)
	CreateAndExportPubKeyBytes(kt kms.KeyType, opts ...kms.KeyOpts) (string, []byte, error)
}

func CreateDID(keyType kms.KeyType, registry vdr.Registry, keyManager keyManager) (*CreateResult, error) {
	methods, err := newVerMethods(3, keyManager, keyType) // nolint:gomnd
	if err != nil {
		return nil, fmt.Errorf("did:orb: failed to create verification methods: %w", err)
	}

	authentication := methods[0]
	assertion := methods[0]
	capabilityDelegation := methods[1]
	capabilityInvocation := methods[2]

	doc := &did.Doc{
		Authentication: []did.Verification{{
			VerificationMethod: *authentication,
			Relationship:       did.Authentication,
			Embedded:           true,
		}},
		AssertionMethod: []did.Verification{{
			VerificationMethod: *assertion,
			Relationship:       did.AssertionMethod,
			Embedded:           true,
		}},
		CapabilityDelegation: []did.Verification{{
			VerificationMethod: *capabilityDelegation,
			Relationship:       did.CapabilityDelegation,
			Embedded:           true,
		}},
		CapabilityInvocation: []did.Verification{{
			VerificationMethod: *capabilityInvocation,
			Relationship:       did.CapabilityInvocation,
			Embedded:           true,
		}},
	}

	keys := [2]interface{}{}
	keyURLs := [2]string{}
	types := [2]string{"update", "recovery"}

	for i := 0; i < 2; i++ {
		keyURLs[i], keys[i], err = key.CryptoKeyCreator(keyType)(keyManager)
		if err != nil {
			return nil, fmt.Errorf("did:orb: failed to create %s key: %w", types[i], err)
		}
	}

	updateKey, _ := keys[0], keyURLs[0]
	recoveryKey, _ := keys[1], keyURLs[1]

	didResolution, err := registry.Create(
		orb.DIDMethod,
		doc,
		vdr.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdr.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
	)

	if err != nil {
		return nil, fmt.Errorf("did:orb: failed to create did: %w", err)
	}

	return &CreateResult{
		DidID: didResolution.DIDDocument.ID,
		KeyID: didResolution.DIDDocument.ID + "#" + assertion.ID,
	}, nil
}

func newVerMethods(count int, km keyManager,
	keyType kms.KeyType) ([]*did.VerificationMethod, error) {
	methods := make([]*did.VerificationMethod, count)

	for i := 0; i < count; i++ {
		keyID, j, err := key.JWKKeyCreator(keyType)(km)
		if err != nil {
			return nil, fmt.Errorf("failed to create key: %w", err)
		}

		vm, err := did.NewVerificationMethodFromJWK(
			keyID,
			crypto.JSONWebKey2020,
			"",
			j,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create verification method: %w", err)
		}

		methods[i] = vm
	}

	return methods, nil
}
