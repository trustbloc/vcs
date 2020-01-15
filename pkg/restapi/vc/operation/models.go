/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

// CreateCrendential input data for edge service issuer rest api
type CreateCrendential struct {
	Subject verifiable.Subject `json:"credentialSubject"`
	Issuer  verifiable.Issuer  `json:"issuer"`
	Type    []string           `json:"type,omitempty"`
}
