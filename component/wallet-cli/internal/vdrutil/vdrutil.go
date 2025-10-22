/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdrutil

import (
	"fmt"
	"strings"

	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/method/jwk"
	didkey "github.com/trustbloc/did-go/method/key"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	longform "github.com/trustbloc/sidetree-go/pkg/vdr/sidetreelongform"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/kms/key"
)

type CreateResult struct {
	DidID string
	KeyID string
}

var DefaultVdrUtil = &VDRUtil{}

type VDRUtil struct {
}

func (v *VDRUtil) Create(
	didMethod string,
	keyType kms.KeyType,
	registry vdrapi.Registry,
	keyCreator api.RawKeyCreator,
) (*CreateResult, error) {
	switch strings.ToLower(didMethod) {
	case "ion":
		return v.createION(keyType, registry, keyCreator)
	case "key":
		return v.CreateKey(keyType, registry, keyCreator)
	case "jwk":
		return v.CreateJWK(keyType, registry, keyCreator)
	default:
		return nil, fmt.Errorf("did method [%v] is not supported", didMethod)
	}
}

func (v *VDRUtil) CreateKey(
	keyType kms.KeyType,
	registry vdrapi.Registry,
	keyCreator api.KeyCreator,
) (*CreateResult, error) {
	verMethod, err := v.newVerMethods(1, keyCreator, keyType)
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

func (v *VDRUtil) CreateJWK(
	keyType kms.KeyType,
	registry vdrapi.Registry,
	keyCreator api.KeyCreator,
) (*CreateResult, error) {
	verMethod, err := v.newVerMethods(1, keyCreator, keyType)
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
		return nil, fmt.Errorf("did:jwk: failed to create did: %w", err)
	}

	return &CreateResult{
		DidID: didResolution.DIDDocument.ID,
		KeyID: didResolution.DIDDocument.ID + "#" + verMethod[0].ID,
	}, nil
}

func (v *VDRUtil) createION(
	keyType kms.KeyType,
	registry vdrapi.Registry,
	keyCreator api.RawKeyCreator,
) (*CreateResult, error) {
	verMethod, err := v.newVerMethods(1, keyCreator, keyType)
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
		keyURLs[i], keys[i], err = key.CryptoKeyCreator(keyCreator)(keyType)
		if err != nil {
			return nil, fmt.Errorf("did:ion: failed to create %s key: %w", types[i], err)
		}
	}

	updateKey, _ := keys[0], keyURLs[0]
	recoveryKey, _ := keys[1], keyURLs[1]

	didResolution, err := registry.Create(
		"ion",
		didDoc,
		vdrapi.WithOption(longform.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(longform.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(longform.VDRAcceptOpt, "long-form"),
	)
	if err != nil {
		return nil, fmt.Errorf("did:ion failed to create long form did: %w", err)
	}

	return &CreateResult{
		DidID: didResolution.DIDDocument.ID,
		KeyID: didResolution.DIDDocument.ID + "#" + vm.ID,
	}, nil
}

func (v *VDRUtil) newVerMethods(count int, keyCreator api.KeyCreator, keyType kms.KeyType,
) ([]*did.VerificationMethod, error) {
	methods := make([]*did.VerificationMethod, count)

	for i := 0; i < count; i++ {
		keyID, j, err := key.JWKKeyCreator(keyCreator)(keyType)
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
