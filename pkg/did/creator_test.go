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
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	vdr2 "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	keymethod "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/stretchr/testify/require"

	did2 "github.com/trustbloc/edge-service/pkg/did"
	"github.com/trustbloc/edge-service/pkg/key"
)

func TestPublicDID(t *testing.T) {
	t.Run("fails if method is not supported", func(t *testing.T) {
		_, err := did2.PublicDID(&did2.Config{Method: "unsupported"})(newKMS(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported did method")
	})

	t.Run("did:trustbloc", func(t *testing.T) {
		t.Run("creates DID", func(t *testing.T) {
			expected := newDIDDoc()
			result, err := did2.PublicDID(&did2.Config{
				Method:                 trustbloc.DIDMethod,
				VerificationMethodType: "JsonWebKey2020",
				VDR:                    &vdr2.MockVDRegistry{CreateValue: expected},
				JWKKeyCreator:          key.JWKKeyCreator(kms.ED25519Type),
				CryptoKeyCreator:       key.CryptoKeyCreator(kms.ED25519Type),
			})(newKMS(t))
			require.NoError(t, err)
			require.Equal(t, result.DIDDocument, expected)
		})

		t.Run("fails if JWKKeyCreator cannot create keys", func(t *testing.T) {
			expected := errors.New("test")
			_, err := did2.PublicDID(&did2.Config{
				Method:                 trustbloc.DIDMethod,
				VerificationMethodType: "JsonWebKey2020",
				JWKKeyCreator: func(kms.KeyManager) (string, *jose.JWK, error) {
					return "", nil, expected
				},
			})(newKMS(t))
			require.ErrorIs(t, err, expected)
		})

		t.Run("fails if CryptoKeyCreator cannot create keys", func(t *testing.T) {
			expected := errors.New("test")
			_, err := did2.PublicDID(&did2.Config{
				Method:                 trustbloc.DIDMethod,
				VerificationMethodType: "JsonWebKey2020",
				VDR:                    newVDR(t, newDIDDoc(), nil),
				JWKKeyCreator:          key.JWKKeyCreator(kms.ED25519Type),
				CryptoKeyCreator: func(kms.KeyManager) (string, interface{}, error) {
					return "", nil, expected
				},
			})(newKMS(t))
			require.ErrorIs(t, err, expected)
		})

		t.Run("fails if VDR cannot create DID", func(t *testing.T) {
			expected := errors.New("test")
			_, err := did2.PublicDID(&did2.Config{
				Method:                 trustbloc.DIDMethod,
				VerificationMethodType: "JsonWebKey2020",
				VDR:                    &vdr2.MockVDRegistry{CreateErr: expected},
				JWKKeyCreator:          key.JWKKeyCreator(kms.ED25519Type),
				CryptoKeyCreator:       key.CryptoKeyCreator(kms.ED25519Type),
			})(newKMS(t))
			require.ErrorIs(t, err, expected)
		})
	})

	t.Run("did:key", func(t *testing.T) {
		t.Run("creates DID", func(t *testing.T) {
			result, err := did2.PublicDID(&did2.Config{
				Method:                 keymethod.DIDMethod,
				VerificationMethodType: "JsonWebKey2020", // TODO the verification method type is probably ignored by did:key
				VDR:                    vdr.New(vdr.WithVDR(keymethod.New())),
				JWKKeyCreator:          key.JWKKeyCreator(kms.ED25519Type),
				CryptoKeyCreator:       key.CryptoKeyCreator(kms.ED25519Type),
			})(newKMS(t))
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(result.DIDDocument.ID, "did:key"))
		})

		t.Run("fails if JWKKeyCreator cannot create keys", func(t *testing.T) {
			expected := errors.New("test")
			_, err := did2.PublicDID(&did2.Config{
				Method:                 keymethod.DIDMethod,
				VerificationMethodType: "JsonWebKey2020",
				JWKKeyCreator: func(kms.KeyManager) (string, *jose.JWK, error) {
					return "", nil, expected
				},
			})(newKMS(t))
			require.ErrorIs(t, err, expected)
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
