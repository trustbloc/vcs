/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

type VerificationResult struct {
	Code           string `json:"code"`
	Message        string `json:"message"`
	IncorrectValue string `json:"incorrect_value"`
}
