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
	VCByte json.RawMessage `json:"vc,omitempty"`
	// UsedIndexes stores the list of used bit indexes in the CSL encoded list.
	UsedIndexes []int `json:"usedIndexes"`
	// ListIDIndex stores the value of ListID.Index obtained by CSLStore.GetLatestListID(),
	// that was topical on a moment the given CSL was created.
	ListIDIndex int `json:"listID"`
	// VC represents parsed CSL.
	VC *verifiable.Credential `json:"-"`
}
