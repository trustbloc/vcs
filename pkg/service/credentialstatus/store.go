/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import "fmt"

type CSLStore interface {
	// GetCSLURL returns the public URL to the CSL.
	GetCSLURL(issuerProfileURL, issuerProfileID string, listIDStr ListIDStr) (string, error)
	// Upsert does C_U_ operations against cslWrapper.
	Upsert(cslWrapper *CSLWrapper) error
	// Get returns CSLWrapper based on URL to the CSL.
	Get(cslURL string) (*CSLWrapper, error)
	// GetLatestListID returns latest ListID, that is topical on a moment given CSL is creating.
	GetLatestListID() (ListID, error)
	// UpdateLatestListID updates underlying ListID.
	UpdateLatestListID(id int) error
}

// ListID is used for the pseudo-random shuffling of suffixes of CSL URL during the credential issuance.
// Values from this structure is common among all issuers.
// In case any Issuer issued startcmd.cslSize credentials
// then ListID.Index is updated to CSLWrapper.ListIDIndex + 1 and stored by CSLStore.UpdateLatestListID().
type ListID struct {
	Index int
	UUID  string
}

// ListIDStr is a string representation of ListID.
type ListIDStr string

// String returns ListIDStr.
func (l ListID) String() ListIDStr {
	return ListIDStr(fmt.Sprintf("%d-%s", l.Index, l.UUID))
}
