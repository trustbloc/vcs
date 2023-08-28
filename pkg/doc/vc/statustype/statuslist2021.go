/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statustype

import (
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	utiltime "github.com/hyperledger/aries-framework-go/component/models/util/time"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"

	vcapi "github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
)

const (
	// statusList2021VCType is the type for status list VC.
	// 	status list VC > Type
	statusList2021VCType = "StatusList2021Credential"
	// StatusList2021VCSubjectType is the subject type of status list VC.
	// 	status list VC > Subject > Type
	StatusList2021VCSubjectType = "StatusList2021"
	// StatusListIndex identifies the bit position of the status value of the VC.
	//  VC > Status > CustomFields key.
	StatusListIndex = "statusListIndex"
	// StatusListCredential stores the link to the status list VC.
	//  VC > Status > CustomFields key.
	StatusListCredential = "statusListCredential"
	// StatusPurpose for StatusList2021.
	//  VC > Status > CustomFields key. Only "revocation" value is supported.
	StatusPurpose = "statusPurpose"
	// StatusList2021Context for StatusList2021.
	StatusList2021Context = "https://w3id.org/vc/status-list/2021/v1"
	// bitStringSize represents the size of compressed bitstring.
	bitStringSize = 128000
	vcType        = "VerifiableCredential"
)

// statusList2021Processor implements f Status List 2021.
// Spec: https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021credential
type statusList2021Processor struct{}

// NewStatusList2021Processor returns new statusList2021Processor.
func NewStatusList2021Processor() *statusList2021Processor { //nolint:revive
	return &statusList2021Processor{}
}

// GetStatusVCURI returns the ID (URL) of status VC.
func (s *statusList2021Processor) GetStatusVCURI(vcStatus *verifiable.TypedID) (string, error) {
	statusListVC, ok := vcStatus.CustomFields[StatusListCredential].(string)
	if !ok {
		return "", fmt.Errorf("failed to cast URI of statusListCredential")
	}

	return statusListVC, nil
}

// GetStatusListIndex returns the bit position of the status value of the VC.
func (s *statusList2021Processor) GetStatusListIndex(vcStatus *verifiable.TypedID) (int, error) {
	revocationListIndex, err := strconv.Atoi(vcStatus.CustomFields[StatusListIndex].(string))
	if err != nil {
		return -1, fmt.Errorf("unable to get statusListIndex: %w", err)
	}

	return revocationListIndex, nil
}

// ValidateStatus validates the status of vc.
func (s *statusList2021Processor) ValidateStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return fmt.Errorf("vc status not exist")
	}

	if vcStatus.Type != string(vcapi.StatusList2021VCStatus) {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	if vcStatus.CustomFields[StatusListIndex] == nil {
		return fmt.Errorf("statusListIndex field not exist in vc status")
	}

	if vcStatus.CustomFields[StatusListCredential] == nil {
		return fmt.Errorf("statusListCredential field not exist in vc status")
	}

	if vcStatus.CustomFields[StatusPurpose] == nil {
		return fmt.Errorf("statusPurpose field not exist in vc status")
	}

	return nil
}

// CreateVCStatus creates verifiable.TypedID.
func (s *statusList2021Processor) CreateVCStatus(statusListIndex, vcID string) *verifiable.TypedID {
	return &verifiable.TypedID{
		ID:   uuid.New().URN(),
		Type: string(vcapi.StatusList2021VCStatus),
		CustomFields: verifiable.CustomFields{
			StatusPurpose:        "revocation",
			StatusListIndex:      statusListIndex,
			StatusListCredential: vcID,
		},
	}
}

// GetVCContext returns VC.Context value appropriate for StatusList2021.
func (s *statusList2021Processor) GetVCContext() string {
	return StatusList2021Context
}

// CreateVC returns *verifiable.Credential appropriate for StatusList2021.
func (s *statusList2021Processor) CreateVC(vcID string, listSize int,
	profile *vcapi.Signer) (*verifiable.Credential, error) {
	credential := &verifiable.Credential{}
	credential.Context = []string{vcutil.DefVCContext, StatusList2021Context}

	vcutil.UpdateSignatureTypeContext(credential, profile.SignatureType)

	credential.ID = vcID
	credential.Types = []string{vcType, statusList2021VCType}
	credential.Issuer = verifiable.Issuer{ID: profile.DID}
	credential.Issued = utiltime.NewTime(time.Now().UTC())

	size := listSize

	if size < bitStringSize {
		size = bitStringSize
	}

	encodeBits, err := bitstring.NewBitString(size).EncodeBits()
	if err != nil {
		return nil, err
	}

	credential.Subject = &credentialSubject{
		ID:            credential.ID + "#list",
		Type:          StatusList2021VCSubjectType,
		StatusPurpose: "revocation",
		EncodedList:   encodeBits,
	}

	return credential, nil
}
