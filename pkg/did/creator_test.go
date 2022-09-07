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
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/kms/key"
)

type keyCreator struct {
	KMS kms.KeyManager

	JWKKeyCreator    func(kt kms.KeyType) func(kms.KeyManager) (string, *jwk.JWK, error)
	CryptoKeyCreator func(kt kms.KeyType) func(kms.KeyManager) (string, interface{}, error)
}

func (k *keyCreator) CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error) {
	return k.JWKKeyCreator(keyType)(k.KMS)
}
func (k *keyCreator) CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error) {
	return k.CryptoKeyCreator(keyType)(k.KMS)
}

func TestPublicDID(t *testing.T) {
	t.Run("fails if method is not supported", func(t *testing.T) {
		creator := did2.NewCreator(&did2.CreatorConfig{})
		_, err := creator.PublicDID("unsupported", "jsonwebsignature2020", kms.ED25519Type,
			&keyCreator{
				KMS: newKMS(t),
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
					KMS:              newKMS(t),
					JWKKeyCreator:    key.JWKKeyCreator,
					CryptoKeyCreator: key.CryptoKeyCreator,
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
					KMS:           newKMS(t),
					JWKKeyCreator: errorJWKKeyCreator,
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
					KMS:              newKMS(t),
					JWKKeyCreator:    key.JWKKeyCreator,
					CryptoKeyCreator: errorCryptoKeyCreator,
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
					KMS:              newKMS(t),
					JWKKeyCreator:    key.JWKKeyCreator,
					CryptoKeyCreator: key.CryptoKeyCreator,
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
				vc.JSONWebSignature2020, kms.ED25519Type, // TODO the verification method type is probably ignored by did:key
				&keyCreator{
					KMS:              newKMS(t),
					JWKKeyCreator:    key.JWKKeyCreator,
					CryptoKeyCreator: key.CryptoKeyCreator,
				})
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(result.DocResolution.DIDDocument.ID, "did:key"))
		})

		t.Run("fails if JWKKeyCreator cannot create keys", func(t *testing.T) {
			expected := errors.New("test")
			creator := did2.NewCreator(&did2.CreatorConfig{})
			_, err := creator.PublicDID(keymethod.DIDMethod, "JsonWebKey2020", kms.ED25519Type,
				&keyCreator{
					KMS:           newKMS(t),
					JWKKeyCreator: errorJWKKeyCreator,
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
					KMS:              newKMS(t),
					JWKKeyCreator:    key.JWKKeyCreator,
					CryptoKeyCreator: key.CryptoKeyCreator,
				})
			require.Error(t, err)
			require.Nil(t, result)
		})
	})
}

func errorJWKKeyCreator(kt kms.KeyType) func(kms.KeyManager) (string, *jwk.JWK, error) {
	return func(km kms.KeyManager) (string, *jwk.JWK, error) {
		return "", nil, errors.New("test")
	}
}

func errorCryptoKeyCreator(kt kms.KeyType) func(kms.KeyManager) (string, interface{}, error) {
	return func(km kms.KeyManager) (string, interface{}, error) {
		return "", nil, errors.New("test")
	}
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
