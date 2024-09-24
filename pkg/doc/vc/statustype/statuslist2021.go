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
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"

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
	// StatusList2021Context for StatusList2021.
	StatusList2021Context = "https://w3id.org/vc/status-list/2021/v1"
	// bitStringSize represents the size of compressed bitstring.
	bitStringSize = 128000
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
		return fmt.Errorf("%s field not exist in vc status", StatusListIndex)
	}

	if vcStatus.CustomFields[StatusListCredential] == nil {
		return fmt.Errorf("%s field not exist in vc status", StatusListCredential)
	}

	if vcStatus.CustomFields[StatusPurpose] == nil {
		return fmt.Errorf("%s field not exist in vc status", StatusPurpose)
	}

	return nil
}

// CreateVCStatus creates verifiable.TypedID.
func (s *statusList2021Processor) CreateVCStatus(index, vcID, purpose string,
	_ ...vcapi.Field) *verifiable.TypedID {
	return &verifiable.TypedID{
		ID:   uuid.New().URN(),
		Type: string(vcapi.StatusList2021VCStatus),
		CustomFields: verifiable.CustomFields{
			StatusPurpose:        purpose,
			StatusListIndex:      index,
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
	vcc := verifiable.CredentialContents{}
	vcc.Context =
		vcutil.AppendSignatureTypeContext(
			[]string{vcutil.DefVCContext, StatusList2021Context}, profile.SignatureType)

	vcc.ID = vcID
	vcc.Types = []string{vcType, statusList2021VCType}
	vcc.Issuer = &verifiable.Issuer{ID: profile.DID}
	vcc.Issued = utiltime.NewTime(time.Now().UTC())

	size := listSize

	if size < bitStringSize {
		size = bitStringSize
	}

	encodeBits, err := bitstring.NewBitString(size).EncodeBits()
	if err != nil {
		return nil, err
	}

	vcc.Subject = toVerifiableSubject(credentialSubject{
		ID:            vcc.ID + "#list",
		Type:          StatusList2021VCSubjectType,
		StatusPurpose: StatusPurposeRevocation,
		EncodedList:   encodeBits,
	})

	return verifiable.CreateCredential(vcc, nil)
}
