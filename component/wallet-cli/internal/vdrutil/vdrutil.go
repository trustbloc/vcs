/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdrutil

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/jwk"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	didkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
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

var DefaultVdrUtil = &VDRUtil{} //nolint

type VDRUtil struct {
}

func (v *VDRUtil) Create(
	didMethod string,
	keyType kms.KeyType,
	registry vdr.Registry,
	keyManager keyManager,
) (*CreateResult, error) {
	switch strings.ToLower(didMethod) {
	case "ion":
		return v.createION(keyType, registry, keyManager)
	case "orb":
		return v.createORB(keyType, registry, keyManager)
	case "key":
		return v.CreateKey(keyType, registry, keyManager)
	case "jwk":
		return v.CreateJWK(keyType, registry, keyManager)
	default:
		return nil, fmt.Errorf("did method [%v] is not supported", didMethod)
	}
}

func (v *VDRUtil) CreateKey(keyType kms.KeyType, registry vdr.Registry, keyManager keyManager) (*CreateResult, error) { //nolint: unparam
	verMethod, err := v.newVerMethods(1, keyManager, keyType)
	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create new ver method: %w", err)
	}

	didResolution, err := registry.Create(
		didkey.DIDMethod,
		&did.Doc{
			VerificationMethod: []did.VerificationMethod{*verMethod[0]},
		},
	)

	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create did: %w", err)
	}

	return &CreateResult{
		DidID: didResolution.DIDDocument.ID,
		KeyID: didResolution.DIDDocument.ID + "#" + verMethod[0].ID,
	}, nil
}

func (v *VDRUtil) CreateJWK(keyType kms.KeyType, registry vdr.Registry, keyManager keyManager) (*CreateResult, error) { //nolint: unparam
	verMethod, err := v.newVerMethods(1, keyManager, keyType)
	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create new ver method: %w", err)
	}

	didResolution, err := registry.Create(
		jwk.DIDMethod,
		&did.Doc{
			VerificationMethod: []did.VerificationMethod{*verMethod[0]},
		},
	)

	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create did: %w", err)
	}

	return &CreateResult{
		DidID: didResolution.DIDDocument.ID,
		KeyID: didResolution.DIDDocument.ID + "#" + verMethod[0].ID,
	}, nil
}

func (v *VDRUtil) createION(keyType kms.KeyType, registry vdr.Registry, keyManager keyManager) (*CreateResult, error) {
	verMethod, err := v.newVerMethods(1, keyManager, keyType)
	if err != nil {
		return nil, fmt.Errorf("did:ion failed to create new ver method: %w", err)
	}

	vm := verMethod[0]

	didDoc := &did.Doc{
		AssertionMethod: []did.Verification{{
			VerificationMethod: *vm,
			Relationship:       did.AssertionMethod,
			Embedded:           true,
		}},
		Authentication: []did.Verification{{
			VerificationMethod: *vm,
			Relationship:       did.Authentication,
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
		"ion",
		didDoc,
		vdr.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdr.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
		vdr.WithOption(longform.VDRAcceptOpt, "long-form"),
	)
	if err != nil {
		return nil, fmt.Errorf("did:ion failed to create long form did: %w", err)
	}

	return &CreateResult{
		DidID: didResolution.DIDDocument.ID,
		KeyID: didResolution.DIDDocument.ID + "#" + vm.ID,
	}, nil
}

func (v *VDRUtil) createORB(keyType kms.KeyType, registry vdr.Registry, keyManager keyManager) (*CreateResult, error) {
	methods, err := v.newVerMethods(3, keyManager, keyType) // nolint:gomnd
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

func (v *VDRUtil) newVerMethods(count int, km keyManager,
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
