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
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	vcapi "github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	"github.com/trustbloc/vcs/pkg/internal/common/utils"
)

const (
	// revocationList2021VCSubjectType is the subject type of status list VC.
	// 	status list VC > Subject > Type
	revocationList2021VCSubjectType = "RevocationList2021"

	// RevocationList2021Context is the context URL for Revocation list 2021.
	RevocationList2021Context = "https://w3c-ccg.github.io/vc-revocation-list-2021/contexts/v1.jsonld"
)

// revocationList2021Processor implements version 0.0.1 of Status list 2021.
// Release: https://github.com/w3c-ccg/vc-status-list-2021/releases/tag/v0.0.1
type revocationList2021Processor struct{}

// NewRevocationList2021Processor returns new revocationList2021Processor.
func NewRevocationList2021Processor() *revocationList2021Processor { //nolint:revive
	return &revocationList2021Processor{}
}

// GetStatusVCURI returns the ID (URL) of status VC.
func (s *revocationList2021Processor) GetStatusVCURI(vcStatus *verifiable.TypedID) (string, error) {
	statusListVC, ok := vcStatus.CustomFields[StatusListCredential].(string)
	if !ok {
		return "", fmt.Errorf("failed to cast URI of statusListCredential")
	}

	return statusListVC, nil
}

// GetStatusListIndex returns the bit position of the status value of the VC.
func (s *revocationList2021Processor) GetStatusListIndex(vcStatus *verifiable.TypedID) (int, error) {
	revocationListIndex, err := strconv.Atoi(vcStatus.CustomFields[StatusListIndex].(string))
	if err != nil {
		return -1, fmt.Errorf("unable to get statusListIndex: %w", err)
	}

	return revocationListIndex, nil
}

// ValidateStatus validates the status of vc.
func (s *revocationList2021Processor) ValidateStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return fmt.Errorf("vc status not exist")
	}

	if vcStatus.Type != string(vcapi.RevocationList2021VCStatus) {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	if vcStatus.CustomFields[StatusListIndex] == nil {
		return fmt.Errorf("statusListIndex field not exist in vc status")
	}

	if vcStatus.CustomFields[StatusListCredential] == nil {
		return fmt.Errorf("statusListCredential field not exist in vc status")
	}

	return nil
}

// CreateVCStatus creates verifiable.TypedID.
// Doc: https://github.com/w3c-ccg/vc-status-list-2021/releases/tag/v0.0.1
func (s *revocationList2021Processor) CreateVCStatus(statusListIndex, vcID string) *verifiable.TypedID {
	return &verifiable.TypedID{
		ID:   uuid.New().URN(),
		Type: string(vcapi.RevocationList2021VCStatus),
		CustomFields: verifiable.CustomFields{
			StatusListIndex:      statusListIndex,
			StatusListCredential: vcID,
		},
	}
}

// GetVCContext returns VC.Context value appropriate for StatusList2021v001.
func (s *revocationList2021Processor) GetVCContext() string {
	return RevocationList2021Context
}

// CreateVC returns *verifiable.Credential appropriate for StatusList2021v001.
func (s *revocationList2021Processor) CreateVC(vcID string, listSize int, //nolint:dupl
	profile *vcapi.Signer) (*verifiable.Credential, error) {
	credential := &verifiable.Credential{}
	credential.Context = []string{vcutil.DefVCContext, RevocationList2021Context}

	vcutil.UpdateSignatureTypeContext(credential, profile.SignatureType)

	credential.ID = vcID
	credential.Types = []string{vcType, statusList2021VCType}
	credential.Issuer = verifiable.Issuer{ID: profile.DID}
	credential.Issued = util.NewTime(time.Now().UTC())

	size := listSize

	if size < bitStringSize {
		size = bitStringSize
	}

	encodeBits, err := utils.NewBitString(size).EncodeBits()
	if err != nil {
		return nil, err
	}

	credential.Subject = &credentialSubject{
		ID:          credential.ID + "#list",
		Type:        revocationList2021VCSubjectType,
		EncodedList: encodeBits,
	}

	return credential, nil
}
