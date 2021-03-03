/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"encoding/json"

	"github.com/trustbloc/edge-core/pkg/zcapld"
	"github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

// Client is the mock edv client
type Client struct {
	edvServerURL                      string
	ReadDocumentError                 error
	ReadDocumentFirstReturnValue      *models.EncryptedDocument
	ReadDocumentSubsequentReturnValue *models.EncryptedDocument
	readDocumentCalledAtLeastOnce     bool
	QueryVaultReturnValue             []string
	CreateVaultError                  error
}

// NewMockEDVClient is the mock version of edv client
func NewMockEDVClient(edvServerURL string, readDocumentFirstReturnValue,
	readDocumentSubsequentReturnValue *models.EncryptedDocument, queryVaultReturnValue []string,
	createVaultError error) *Client {
	return &Client{edvServerURL: edvServerURL, ReadDocumentSubsequentReturnValue: readDocumentSubsequentReturnValue,
		ReadDocumentFirstReturnValue: readDocumentFirstReturnValue,
		QueryVaultReturnValue:        queryVaultReturnValue,
		CreateVaultError:             createVaultError}
}

// CreateDataVault creates a new data vault.
func (c *Client) CreateDataVault(config *models.DataVaultConfiguration,
	opts ...client.ReqOption) (string, []byte, error) {
	bytes, err := json.Marshal(&zcapld.Capability{})
	if err != nil {
		return "", nil, err
	}

	return "", bytes, c.CreateVaultError
}

// CreateDocument stores the specified document.
func (c *Client) CreateDocument(vaultID string, document *models.EncryptedDocument,
	opts ...client.ReqOption) (string, error) {
	return "", nil
}

// ReadDocument mocks a ReadDocument call. It never returns an error.
func (c *Client) ReadDocument(vaultID, docID string, opts ...client.ReqOption) (*models.EncryptedDocument, error) {
	if !c.readDocumentCalledAtLeastOnce {
		c.readDocumentCalledAtLeastOnce = true

		return c.ReadDocumentFirstReturnValue, c.ReadDocumentError
	}

	return c.ReadDocumentSubsequentReturnValue, c.ReadDocumentError
}

// QueryVault mocks a vault query call. It never returns an error.
func (c *Client) QueryVault(vaultID, name, value string, opts ...client.ReqOption) ([]string, error) {
	return c.QueryVaultReturnValue, nil
}
