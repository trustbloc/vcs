/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didbloc

import "github.com/hyperledger/aries-framework-go/pkg/doc/did"

// Client is the mock did bloc client
type Client struct {
	CreateDIDValue *did.Doc
	CreateDIDErr   error
}

// CreateDID create did
func (c *Client) CreateDID(domain string) (*did.Doc, error) {
	return c.CreateDIDValue, c.CreateDIDErr
}
