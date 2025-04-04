/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"github.com/trustbloc/vc-go/verifiable"
)

// StatusType is used to define implementation of VC status list.
// Field verifiable.TypedID .Type.
type StatusType string

const (
	// StatusList2021VCStatus represents the implementation of VC Status List 2021.
	//  VC > Status > Type
	// 	Doc: https://w3c-ccg.github.io/vc-status-list-2021/
	StatusList2021VCStatus StatusType = "StatusList2021Entry"

	// RevocationList2021VCStatus represents the implementation of VC Status List 2021 v.0.0.1.
	//  VC > Status > Type
	//  Doc: https://github.com/w3c-ccg/vc-status-list-2021/releases/tag/v0.0.1
	RevocationList2021VCStatus StatusType = "RevocationList2021Status"

	// RevocationList2020VCStatus represents the implementation of VC Revocation List 2020.
	//  VC > Status > Type
	// 	Doc: https://w3c-ccg.github.io/vc-status-rl-2020/
	RevocationList2020VCStatus StatusType = "RevocationList2020Status"

	// BitstringStatusList represents the implementation of the Bitstring VC Status List.
	//  VC > Status > Type
	// 	Doc: https://www.w3.org/TR/vc-bitstring-status-list/
	BitstringStatusList StatusType = "BitstringStatusListEntry"
)

// Field is used to define the key-value pair for additional fields in VC.
type Field struct {
	Key   string
	Value interface{}
}

// StatusProcessor holds the list of methods required for processing different versions of Status(Revocation) List VC.
type StatusProcessor interface {
	ValidateStatus(vcStatus *verifiable.TypedID) error
	GetStatusVCURI(vcStatus *verifiable.TypedID) (string, error)
	GetStatusListIndex(vcStatus *verifiable.TypedID) (int, error)
	CreateVC(vcID string, listSize int, statusPurpose string, profile *Signer) (*verifiable.Credential, error)
	CreateVCStatus(index, vcID, statusPurpose string, additionalFields ...Field) *verifiable.TypedID
	GetVCContext() string
	UpdateStatus(vc *verifiable.Credential, status bool, indexes ...int) (*verifiable.Credential, error)
	IsSet(vc *verifiable.Credential, index int) (bool, error)
	GetStatusPurpose(vcStatus *verifiable.TypedID) (string, error)
}

type StatusProcessorGetter func(vcStatusListType StatusType) (StatusProcessor, error)
