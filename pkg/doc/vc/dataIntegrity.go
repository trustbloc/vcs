/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

// DataIntegrityProofConfig represents the Data Integrity LDP config.
type DataIntegrityProofConfig struct {
	// Enable flag enables Data Integrity Proof feature.
	Enable bool `json:"enable"`
	// SuiteType is the data integrity Type identifier for the suite.
	SuiteType string `json:"suiteType"`
}
