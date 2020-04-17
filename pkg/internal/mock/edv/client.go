/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

// Client is the mock edv client
type Client struct {
	edvServerURL                      string
	ReadDocumentFirstReturnValue      *models.EncryptedDocument
	ReadDocumentSubsequentReturnValue *models.EncryptedDocument
	readDocumentCalledAtLeastOnce     bool
	QueryVaultReturnValue             []string
}

// NewMockEDVClient is the mock version of edv client
func NewMockEDVClient(edvServerURL string, readDocumentFirstReturnValue,
	readDocumentSubsequentReturnValue *models.EncryptedDocument, queryVaultReturnValue []string) *Client {
	return &Client{edvServerURL: edvServerURL, ReadDocumentSubsequentReturnValue: readDocumentSubsequentReturnValue,
		ReadDocumentFirstReturnValue: readDocumentFirstReturnValue,
		QueryVaultReturnValue:        queryVaultReturnValue}
}

// CreateDataVault creates a new data vault.
func (c *Client) CreateDataVault(config *models.DataVaultConfiguration) (string, error) {
	return "", nil
}

// CreateDocument stores the specified document.
func (c *Client) CreateDocument(vaultID string, document *models.EncryptedDocument) (string, error) {
	return "", nil
}

// ReadDocument mocks a ReadDocument call. It never returns an error.
func (c *Client) ReadDocument(vaultID, docID string) (*models.EncryptedDocument, error) {
	if !c.readDocumentCalledAtLeastOnce {
		c.readDocumentCalledAtLeastOnce = true

		return c.ReadDocumentFirstReturnValue, nil
	}

	return c.ReadDocumentSubsequentReturnValue, nil
}

// QueryVault mocks a vault query call. It never returns an error.
func (c *Client) QueryVault(vaultID string, query *models.Query) ([]string, error) {
	return c.QueryVaultReturnValue, nil
}
