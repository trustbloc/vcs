/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"encoding/json"
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

var (
	ErrDataNotFound = errors.New("data not found")
)

// CSL (Credential Status List) - is a verifiable.Credential that stores the
// revocation status of credentials issued by Issuer.
//
//	This type is created for the documentation purpose.
type CSL string

// CSLWrapper contains CSL and metadata.
type CSLWrapper struct {
	// VCByte stores the CSL.
	VCByte json.RawMessage `json:"vc"`
	// Size represents the amount of credentials that Issuer issued using given CSL.
	Size int `json:"size"`
	// RevocationListIndex represents the bit position in CSL that stores the status of certain credential.
	RevocationListIndex int `json:"revocationListIndex"`
	// ListID stores the ID of the List, that was topical on a moment the given CSL was created.
	// ID of the List is a common among Issuers integer value.
	// In case any Issuer issued startcmd.cslSize credentials (Size equals startcmd.cslSize) then ID of the List is
	// updated by one.
	ListID int `json:"listID"`
	// VC represents parsed CSL.
	VC *verifiable.Credential `json:"-"`
}
