/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

type CSLStore interface {
	// GetCSLURL returns the public URL to the CSL.
	GetCSLURL(issuerProfileURL, issuerProfileID string, statusListID ListID) (string, error)
	// Upsert does C_U_ operations against cslWrapper.
	Upsert(cslWrapper *CSLWrapper) error
	// Get returns CSLWrapper based on URL to the CSL.
	Get(cslURL string) (*CSLWrapper, error)
	// GetLatestListID returns latest ListID, that is topical on a moment given CSL is creating.
	GetLatestListID() (ListID, error)
	// UpdateLatestListID updates underlying ListID.
	UpdateLatestListID() error

	DeleteLatestListID() error
}

// ListID is used for the pseudo-random shuffling of suffixes of CSL URL during the credential issuance.
// The value of ListID is common among all issuers.
// In case any Issuer issued startcmd.cslSize credentials then ListID is updated.
type ListID string
