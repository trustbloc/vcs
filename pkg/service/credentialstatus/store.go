/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import "context"

type CSLVCStore interface {
	// GetCSLURL returns the public URL to the CSL.
	GetCSLURL(issuerProfileURL, externalIssuerProfileID string, statusListID ListID) (string, error)
	// Upsert updates CSL VC wrapper.
	Upsert(ctx context.Context, cslURL string, wrapper *CSLVCWrapper) error
	// Get returns CSL VC wrapper based on URL to the CSL.
	Get(ctx context.Context, cslURL string) (*CSLVCWrapper, error)
}

type CSLIndexStore interface {
	// Upsert updates CSL Indexes.
	Upsert(ctx context.Context, cslURL string, cslWrapper *CSLIndexWrapper) error
	// Get returns CSLIndexWrapper based on URL to the CSL.
	Get(ctx context.Context, cslURL string) (*CSLIndexWrapper, error)
	// GetLatestListID returns latest ListID, that is topical on a moment given CSL is creating.
	GetLatestListID(ctx context.Context) (ListID, error)
	// UpdateLatestListID updates underlying ListID.
	UpdateLatestListID(ctx context.Context) error
}

// ListID is used for the pseudo-random shuffling of suffixes of CSL URL during the credential issuance.
// The value of ListID is common among all issuers.
// In case any Issuer issued startcmd.cslSize credentials then ListID is updated.
type ListID string
