/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"

	"github.com/trustbloc/edge-service/pkg/client/vault"
)

func TestNewDocumentReader(t *testing.T) {
	r := vault.NewDocumentReader(
		"vaultID",
		"docID",
		&mockEDVClient{},
		vault.WithDocumentDecrypter(&mockJWEDecrypter{}),
	)

	require.NotNil(t, r)
}

func TestDocumentReader_Read(t *testing.T) {
	t.Run("reads plaintext EDV document", func(t *testing.T) {
		expected := []byte(uuid.New().String())
		r := newReader(&mockEDVClient{
			doc: &models.EncryptedDocument{
				JWE: serializeFull(t, plaintextJWE(expected)),
			},
		})
		result := bytes.NewBuffer(nil)

		_, err := io.Copy(result, r)
		require.NoError(t, err)

		require.Equal(t, expected, result.Bytes())
	})

	t.Run("reads encrypted EDV document", func(t *testing.T) {
		expected := []byte(uuid.New().String())
		agent := newAgent(t)

		jwe := encryptedJWE(t, agent, expected)

		r := newReader(
			&mockEDVClient{doc: &models.EncryptedDocument{JWE: serializeFull(t, jwe)}},
			vault.WithDocumentDecrypter(jose.NewJWEDecrypt(nil, agent.Crypto(), agent.KMS())),
		)
		result := bytes.NewBuffer(nil)

		_, err := io.Copy(result, r)
		require.NoError(t, err)

		require.Equal(t, expected, result.Bytes())
	})

	t.Run("wraps error from Confidential Storage client", func(t *testing.T) {
		expected := errors.New("test")
		r := newReader(&mockEDVClient{err: expected})
		n, err := r.Read(nil)
		require.Zero(t, n)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error on invalid format for serialized JWE", func(t *testing.T) {
		r := newReader(&mockEDVClient{doc: &models.EncryptedDocument{JWE: []byte("INVALID")}})
		n, err := r.Read(nil)
		require.Zero(t, n)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to deserialize confidential storage document jwe")
	})

	t.Run("wraps error from the decrypter", func(t *testing.T) {
		expected := errors.New("test")
		r := newReader(
			&mockEDVClient{doc: &models.EncryptedDocument{JWE: serializeFull(t, plaintextJWE([]byte("test")))}},
			vault.WithDocumentDecrypter(&mockJWEDecrypter{err: expected}),
		)
		n, err := r.Read(nil)
		require.Zero(t, n)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("behaves like io.Reader", func(t *testing.T) {
		t.Run("with zero-length input buffer", func(t *testing.T) {
			expected := []byte(uuid.New().String())
			buf := make([]byte, 0)
			agent := newAgent(t)
			r := newReader(
				&mockEDVClient{
					doc: &models.EncryptedDocument{JWE: serializeFull(t, encryptedJWE(t, agent, expected))},
				},
				vault.WithDocumentDecrypter(jose.NewJWEDecrypt(nil, agent.Crypto(), agent.KMS())),
			)

			n, err := r.Read(buf)
			require.Zero(t, n)
			require.NoError(t, err)

			n, err = r.Read(buf)
			require.Zero(t, n)
			require.NoError(t, err)

			// contents should still be readable
			buf = make([]byte, len(expected))
			n, err = r.Read(buf)
			require.Equal(t, len(expected), n)
			require.NoError(t, err)
			require.Equal(t, expected, buf)
		})

		t.Run("partial reads", func(t *testing.T) {
			expected := []byte(uuid.New().String())
			agent := newAgent(t)
			r := newReader(
				&mockEDVClient{
					doc: &models.EncryptedDocument{JWE: serializeFull(t, encryptedJWE(t, agent, expected))},
				},
				vault.WithDocumentDecrypter(jose.NewJWEDecrypt(nil, agent.Crypto(), agent.KMS())),
			)

			buf := make([]byte, 1)
			require.Less(t, len(buf), len(expected))

			result := make([]byte, 0)

			var n int
			var err error

			for err == nil {
				n, err = r.Read(buf)
				if err != nil {
					require.True(t, errors.Is(err, io.EOF))
					require.Zero(t, n)

					break
				}

				require.Equal(t, len(buf), n)
				result = append(result, buf...)
			}

			require.Equal(t, expected, result)
		})
	})
}

type mockEDVClient struct {
	doc *models.EncryptedDocument
	err error
}

func (m *mockEDVClient) ReadDocument(_, _ string, _ ...client.ReqOption) (*models.EncryptedDocument, error) {
	return m.doc, m.err
}

type mockJWEDecrypter struct {
	plaintext []byte
	err       error
}

func (m *mockJWEDecrypter) Decrypt(_ *jose.JSONWebEncryption) ([]byte, error) {
	return m.plaintext, m.err
}

func newReader(r vault.ConfidentialStorageDocReader, opts ...vault.ReaderOption) *vault.DocumentReader {
	return vault.NewDocumentReader("", "", r, opts...)
}

func plaintextJWE(msg []byte) *jose.JSONWebEncryption {
	return &jose.JSONWebEncryption{
		ProtectedHeaders: map[string]interface{}{},
		Recipients:       []*jose.Recipient{{}},
		Ciphertext:       base64.RawURLEncoding.EncodeToString(msg),
	}
}

func encryptedJWE(t *testing.T, agent *context.Provider, msg []byte) *jose.JSONWebEncryption {
	_, rawPubKey, err := agent.KMS().CreateAndExportPubKeyBytes(kms.NISTP256ECDHKWType)
	require.NoError(t, err)

	recipientKey := &crypto.PublicKey{}
	err = json.Unmarshal(rawPubKey, recipientKey)
	require.NoError(t, err)

	jweEncrpt, err := jose.NewJWEEncrypt(
		jose.A256GCM,
		"",
		"",
		nil,
		[]*crypto.PublicKey{recipientKey},
		agent.Crypto(),
	)
	require.NoError(t, err)

	jwe, err := jweEncrpt.Encrypt(msg)
	require.NoError(t, err)

	return jwe
}

func serializeFull(t *testing.T, jwe *jose.JSONWebEncryption) []byte {
	t.Helper()

	s, err := jwe.FullSerialize(json.Marshal)
	require.NoError(t, err)

	return []byte(s)
}

func newAgent(t *testing.T) *context.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}
