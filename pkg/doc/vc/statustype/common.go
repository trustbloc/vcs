/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statustype

import "github.com/trustbloc/vc-go/verifiable"

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
		vcSub.CustomFields["statusPurpose"] = subject.StatusPurpose
	}

	return []verifiable.Subject{vcSub}
}
