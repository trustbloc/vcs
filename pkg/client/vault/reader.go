/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

// ConfidentialStorageDocReader reads encrypted documents from Confidential Storages.
type ConfidentialStorageDocReader interface {
	ReadDocument(vaultID, docID string, opts ...edv.ReqOption) (*models.EncryptedDocument, error)
}

// ReaderOption configures the DocumentReader.
type ReaderOption func(*DocumentReader)

// WithDocumentDecrypter must be used when the Confidential Storage document has been encrypted.
func WithDocumentDecrypter(jd jose.Decrypter) ReaderOption {
	return func(r *DocumentReader) {
		r.jweDecrypter = jd
	}
}

// NewDocumentReader returns a non thread-safe Reader for the Confidential Storage document.
//
// If the Confidential Storage document is encrypted then use the WithDocumentDecrypter ReaderOption to decrypt the contents.
func NewDocumentReader(vaultID, docID string, client ConfidentialStorageDocReader, options ...ReaderOption) *DocumentReader {
	r := &DocumentReader{
		client:       client,
		vaultID:      vaultID,
		docID:        docID,
		jweDecrypter: &noopJWEDecrypter{},
	}

	for _, opt := range options {
		opt(r)
	}

	return r
}

// DocumentReader is an io.Reader encapsulating the contents of a Confidential Storage document.
type DocumentReader struct {
	client       ConfidentialStorageDocReader
	vaultID      string
	docID        string
	jweDecrypter jose.Decrypter
	buf          *bytes.Buffer
}

func (r *DocumentReader) Read(p []byte) (n int, err error) {
	if r.buf != nil {
		return r.buf.Read(p)
	}

	encryptedDoc, err := r.client.ReadDocument(r.vaultID, r.docID)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch confidential storage document: %w", err)
	}

	jwe, err := jose.Deserialize(string(encryptedDoc.JWE))
	if err != nil {
		return 0, fmt.Errorf("failed to deserialize confidential storage document jwe: %w", err)
	}

	plaintext, err := r.jweDecrypter.Decrypt(jwe)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt the confidential storage document jwe: %w", err)
	}

	r.buf = bytes.NewBuffer(plaintext)

	return r.buf.Read(p)
}

type noopJWEDecrypter struct {
}

func (n *noopJWEDecrypter) Decrypt(jwe *jose.JSONWebEncryption) ([]byte, error) {
	return base64.URLEncoding.DecodeString(jwe.Ciphertext)
}
