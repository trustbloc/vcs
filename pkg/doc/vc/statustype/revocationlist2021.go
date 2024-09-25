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
	switch t := vcStatus.CustomFields[StatusListIndex].(type) {
	case string:
		revocationListIndex, err := strconv.Atoi(t)
		if err != nil {
			return -1, fmt.Errorf("unable to get statusListIndex: %w", err)
		}

		return revocationListIndex, nil
	case float64:
		return int(t), nil
	case int:
		return t, nil
	default:
		return -1, fmt.Errorf("unsupported statusListIndex type %+v", t)
	}
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
func (s *revocationList2021Processor) CreateVCStatus(index, vcID, _ string,
	_ ...vcapi.Field) *verifiable.TypedID {
	return &verifiable.TypedID{
		ID:   uuid.New().URN(),
		Type: string(vcapi.RevocationList2021VCStatus),
		CustomFields: verifiable.CustomFields{
			StatusListIndex:      index,
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
	vcc := verifiable.CredentialContents{}
	vcc.Context =
		vcutil.AppendSignatureTypeContext(
			[]string{vcutil.DefVCContext, RevocationList2021Context}, profile.SignatureType)

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
		ID:          vcc.ID + "#list",
		Type:        revocationList2021VCSubjectType,
		EncodedList: encodeBits,
	})

	return verifiable.CreateCredential(vcc, nil)
}
