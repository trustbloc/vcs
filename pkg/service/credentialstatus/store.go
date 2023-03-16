/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import "context"

type CSLStore interface {
	// GetCSLURL returns the public URL to the CSL.
	GetCSLURL(issuerProfileURL, externalIssuerProfileID string, statusListID ListID) (string, error)
	// Upsert does C_U_ operations against cslWrapper.
	Upsert(ctx context.Context, cslWrapper *CSLWrapper) error
	// Get returns CSLWrapper based on URL to the CSL.
	Get(ctx context.Context, cslURL string) (*CSLWrapper, error)
	// GetLatestListID returns latest ListID, that is topical on a moment given CSL is creating.
	GetLatestListID(ctx context.Context) (ListID, error)
	// UpdateLatestListID updates underlying ListID.
	UpdateLatestListID(ctx context.Context) error
}

// ListID is used for the pseudo-random shuffling of suffixes of CSL URL during the credential issuance.
// The value of ListID is common among all issuers.
// In case any Issuer issued startcmd.cslSize credentials then ListID is updated.
type ListID string
