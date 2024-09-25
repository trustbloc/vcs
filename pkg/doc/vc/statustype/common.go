/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statustype

import "github.com/trustbloc/vc-go/verifiable"

const (
	vcType = "VerifiableCredential"

	// StatusListIndex identifies the bit position of the status value of the VC.
	//  VC > Status > CustomFields key.
	StatusListIndex = "statusListIndex"
	// StatusListCredential stores the link to the status list VC.
	//  VC > Status > CustomFields key.
	StatusListCredential = "statusListCredential"
	// StatusPurpose for StatusList2021.
	//  VC > Status > CustomFields key. Only "revocation" value is supported.
	StatusPurpose = "statusPurpose"

	StatusPurposeRevocation = "revocation"
	StatusPurposeSuspension = "suspension"
	StatusPurposeMessage    = "statusMessage"

	StatusMessage   = "statusMessage"
	StatusSize      = "statusSize"
	StatusReference = "statusReference"
)

type credentialSubject struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	StatusPurpose string `json:"statusPurpose,omitempty"`
	EncodedList   string `json:"encodedList"`
}

func toVerifiableSubject(subject credentialSubject) []verifiable.Subject {
	vcSub := verifiable.Subject{
		ID: subject.ID,
		CustomFields: verifiable.CustomFields{
			"type":        subject.Type,
			"encodedList": subject.EncodedList,
		},
	}
	if subject.StatusPurpose != "" {
		vcSub.CustomFields[StatusPurpose] = subject.StatusPurpose
	}

	return []verifiable.Subject{vcSub}
}
