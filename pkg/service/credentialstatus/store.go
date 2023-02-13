/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

type CSLStore interface {
	// GetCSLURL returns the public URL to the CSL.
	GetCSLURL(issuerProfileURL, issuerProfileID, statusID string) (string, error)
	// Upsert does C_U_ operations against cslWrapper.
	Upsert(cslWrapper *CSLWrapper) error
	// Get returns CSLWrapper based on URL to the CSL.
	Get(cslURL string) (*CSLWrapper, error)
	UpdateLatestListID(id int) error
	GetLatestListID() (int, error)
}
