/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	vdr2 "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	keymethod "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/stretchr/testify/require"

	did2 "github.com/trustbloc/vcs/pkg/did"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms/key"
)

type keyCreator struct {
	kms                   kms.KeyManager
	errorJWKKeyCreator    bool
	errorCryptoKeyCreator bool
}

func (k *keyCreator) CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error) {
	if k.errorJWKKeyCreator {
		return "", nil, errors.New("test")
	}

	return key.JWKKeyCreator(keyType)(k.kms)
}
func (k *keyCreator) CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error) {
	if k.errorCryptoKeyCreator {
		return "", nil, errors.New("test")
	}

	return key.CryptoKeyCreator(keyType)(k.kms)
}

func TestPublicDID(t *testing.T) {
	t.Run("fails if method is not supported", func(t *testing.T) {
		creator := did2.NewCreator(&did2.CreatorConfig{})
		_, err := creator.PublicDID("unsupported", "jsonwebsignature2020", kms.ED25519Type,
			&keyCreator{
				kms: newKMS(t),
			})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported did method")
	})

	t.Run("did:trustbloc", func(t *testing.T) {
		t.Run("creates DID", func(t *testing.T) {
			expected := newDIDDoc()
			creator := did2.NewCreator(&did2.CreatorConfig{
				VDR: &vdr2.MockVDRegistry{CreateValue: expected},
			})

			result, err := creator.PublicDID(
				orb.DIDMethod, "jsonwebsignature2020", kms.ED25519Type,
				&keyCreator{
					kms: newKMS(t),
				})
			require.NoError(t, err)
			require.Equal(t, result.DocResolution.DIDDocument, expected)
		})

		t.Run("fails if JWKKeyCreator cannot create keys", func(t *testing.T) {
			expected := errors.New("test")
			creator := did2.NewCreator(&did2.CreatorConfig{})
			_, err := creator.PublicDID(orb.DIDMethod,
				"jsonwebsignature2020", kms.ED25519Type,
				&keyCreator{
					kms:                newKMS(t),
					errorJWKKeyCreator: true,
				})
			require.Contains(t, err.Error(), expected.Error())
		})

		t.Run("fails if CryptoKeyCreator cannot create keys", func(t *testing.T) {
			expected := errors.New("test")
			creator := did2.NewCreator(&did2.CreatorConfig{
				VDR: newVDR(t, newDIDDoc(), nil),
			})
			_, err := creator.PublicDID(orb.DIDMethod,
				"jsonwebsignature2020", kms.ED25519Type,
				&keyCreator{
					kms:                   newKMS(t),
					errorCryptoKeyCreator: true,
				})
			require.Contains(t, err.Error(), expected.Error())
		})

		t.Run("fails if VDR cannot create DID", func(t *testing.T) {
			expected := errors.New("test")
			creator := did2.NewCreator(&did2.CreatorConfig{
				VDR: &vdr2.MockVDRegistry{CreateErr: expected},
			})
			_, err := creator.PublicDID(
				orb.DIDMethod,
				"jsonwebsignature2020", kms.ED25519Type,
				&keyCreator{
					kms: newKMS(t),
				})
			require.ErrorIs(t, err, expected)
		})
	})

	t.Run("did:key", func(t *testing.T) {
		t.Run("creates DID", func(t *testing.T) {
			creator := did2.NewCreator(&did2.CreatorConfig{
				VDR: vdr.New(vdr.WithVDR(keymethod.New())),
			})
			result, err := creator.PublicDID(keymethod.DIDMethod,
				// TODO the verification method type is probably ignored by did:key
				vcsverifiable.JSONWebSignature2020, kms.ED25519Type,
				&keyCreator{
					kms: newKMS(t),
				})
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(result.DocResolution.DIDDocument.ID, "did:key"))
		})

		t.Run("fails if JWKKeyCreator cannot create keys", func(t *testing.T) {
			expected := errors.New("test")
			creator := did2.NewCreator(&did2.CreatorConfig{})
			_, err := creator.PublicDID(keymethod.DIDMethod, "JsonWebKey2020", kms.ED25519Type,
				&keyCreator{
					kms:                newKMS(t),
					errorJWKKeyCreator: true,
				})
			require.Contains(t, err.Error(), expected.Error())
		})
	})

	t.Run("did:web", func(t *testing.T) {
		t.Run("creates DID", func(t *testing.T) {
			creator := did2.NewCreator(&did2.CreatorConfig{
				VDR: vdr.New(vdr.WithVDR(keymethod.New())),
			})
			result, err := creator.PublicDID("web",
				"JsonWebKey2020", kms.ED25519Type, // TODO the verification method type is probably ignored by did:key
				&keyCreator{
					kms: newKMS(t),
				})
			require.Error(t, err)
			require.Nil(t, result)
		})
	})
}

func newKMS(t *testing.T) kms.KeyManager {
	t.Helper()

	a, err := aries.New(aries.WithStoreProvider(mem.NewProvider()))
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx.KMS()
}

func newDIDDoc() *did.Doc {
	return &did.Doc{
		ID: fmt.Sprintf("did:example:%s", uuid.New().String()),
	}
}

func newVDR(t *testing.T, d *did.Doc, err error) vdrapi.Registry {
	t.Helper()

	return &vdr2.MockVDRegistry{
		CreateValue: d,
		CreateErr:   err,
	}
}
