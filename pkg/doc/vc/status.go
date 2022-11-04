/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

// StatusVersion is used to define implementation of VC status list.
// Field verifiable.TypedID .Type.
type StatusVersion string

const (
	// StatusList2021VCStatus represents the implementation of VC Status List 2021.
	//  VC > Status > Type
	// 	Doc: https://w3c-ccg.github.io/vc-status-list-2021/
	StatusList2021VCStatus StatusVersion = "StatusList2021Entry"

	// RevocationList2021VCStatus represents the implementation of VC Status List 2021 v.0.0.1.
	//  VC > Status > Type
	//  Doc: https://github.com/w3c-ccg/vc-status-list-2021/releases/tag/v0.0.1
	RevocationList2021VCStatus StatusVersion = "RevocationList2021Status"

	// RevocationList2020VCStatus represents the implementation of VC Revocation List 2020.
	//  VC > Status > Type
	// 	Doc: https://w3c-ccg.github.io/vc-status-rl-2020/
	RevocationList2020VCStatus StatusVersion = "RevocationList2020Status"
)
