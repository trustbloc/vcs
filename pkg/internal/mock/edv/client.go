/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
)

// Client is the mock edv client
type Client struct {
	edvServerURL            string
	readDocumentReturnValue []byte
}

// NewMockEDVClient is the mock version of edv client
func NewMockEDVClient(edvServerURL string, readDocumentReturnValue []byte) *Client {
	return &Client{edvServerURL: edvServerURL, readDocumentReturnValue: readDocumentReturnValue}
}

// CreateDataVault creates a new data vault.
func (c *Client) CreateDataVault(config *operation.DataVaultConfiguration) (string, error) {
	return "", nil
}

// CreateDocument stores the specified document.
func (c *Client) CreateDocument(vaultID string, document *operation.StructuredDocument) (string, error) {
	return "", nil
}

// ReadDocument reads the specified document.
func (c *Client) ReadDocument(vaultID, docID string) ([]byte, error) {
	return c.readDocumentReturnValue, nil
}
