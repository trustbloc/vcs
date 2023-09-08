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
	revocationList2020VCType = "RevocationList2020Credential"
	// revocationList2020VCSubjectType is the subject type of revocation list VC.
	// 	revocation list VC > Subject > Type
	revocationList2020VCSubjectType = "RevocationList2020"
	// RevocationListIndex identifies the bit position of the status value of the VC.
	//  VC > Status > CustomFields key.
	RevocationListIndex = "revocationListIndex"
	// RevocationListCredential stores the link to the revocation list VC.
	//  VC > Status > CustomFields key.
	RevocationListCredential = "revocationListCredential"

	RevocationList2020Context = "https://w3id.org/vc-revocation-list-2020/v1"
)

// revocationList2020Processor implements Revocation List 2020.
// Spec: https://w3c-ccg.github.io/vc-status-rl-2020/
type revocationList2020Processor struct{}

// NewRevocationList2020Processor returns new revocationList2020Processor.
func NewRevocationList2020Processor() *revocationList2020Processor { //nolint:revive
	return &revocationList2020Processor{}
}

// GetStatusVCURI returns the ID (URL) of status VC.
func (s *revocationList2020Processor) GetStatusVCURI(vcStatus *verifiable.TypedID) (string, error) {
	statusListVC, ok := vcStatus.CustomFields[RevocationListCredential].(string)
	if !ok {
		return "", fmt.Errorf("failed to cast URI of revocationListCredential")
	}

	return statusListVC, nil
}

// GetStatusListIndex returns the bit position of the status value of the VC.
func (s *revocationList2020Processor) GetStatusListIndex(vcStatus *verifiable.TypedID) (int, error) {
	revocationListIndex, err := strconv.Atoi(vcStatus.CustomFields[RevocationListIndex].(string))
	if err != nil {
		return -1, fmt.Errorf("unable to get revocationListIndex: %w", err)
	}

	return revocationListIndex, nil
}

// ValidateStatus validates the status of vc.
func (s *revocationList2020Processor) ValidateStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return fmt.Errorf("vc status not exist")
	}

	if vcStatus.Type != string(vcapi.RevocationList2020VCStatus) {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	if vcStatus.CustomFields[RevocationListIndex] == nil {
		return fmt.Errorf("statusListIndex field not exist in vc status")
	}

	if vcStatus.CustomFields[RevocationListCredential] == nil {
		return fmt.Errorf("statusListCredential field not exist in vc status")
	}

	return nil
}

// CreateVCStatus creates verifiable.TypedID.
func (s *revocationList2020Processor) CreateVCStatus(revocationListIndex, vcID string) *verifiable.TypedID {
	return &verifiable.TypedID{
		ID:   uuid.New().URN(),
		Type: string(vcapi.RevocationList2020VCStatus),
		CustomFields: verifiable.CustomFields{
			RevocationListIndex:      revocationListIndex,
			RevocationListCredential: vcID,
		},
	}
}

// GetVCContext returns VC.Context value appropriate for RevocationList2020.
func (s *revocationList2020Processor) GetVCContext() string {
	return RevocationList2020Context
}

// CreateVC returns *verifiable.Credential appropriate for RevocationList2020.
func (s *revocationList2020Processor) CreateVC(vcID string, listSize int, //nolint:dupl
	profile *vcapi.Signer) (*verifiable.Credential, error) {
	credential := &verifiable.Credential{}
	credential.Context = []string{vcutil.DefVCContext, RevocationList2020Context}

	vcutil.UpdateSignatureTypeContext(credential, profile.SignatureType)

	credential.ID = vcID
	credential.Types = []string{vcType, revocationList2020VCType}
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
		ID:          credential.ID + "#list",
		Type:        revocationList2020VCSubjectType,
		EncodedList: encodeBits,
	}

	return credential, nil
}
