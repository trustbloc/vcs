/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import "time"

// UNIRegistrar uni-registrar
type UNIRegistrar struct {
	DriverURL string            `json:"driverURL,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
}

// ErrorResponse to send error message in the response
type ErrorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

// DataProfile struct for profile
type DataProfile struct { // nolint: unused
	Name                    string     `json:"name,omitempty"`
	DID                     string     `json:"did,omitempty"`
	URI                     string     `json:"uri,omitempty"`
	SignatureType           string     `json:"signatureType,omitempty"`
	SignatureRepresentation int        `json:"signatureRepresentation,omitempty"`
	Creator                 string     `json:"creator,omitempty"`
	Created                 *time.Time `json:"created,omitempty"`
	DIDPrivateKey           string     `json:"didPrivateKey,omitempty"`
}
