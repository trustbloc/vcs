/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statustype

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/multiformats/go-multibase"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"

	vcapi "github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
)

const (
	// StatusListBitstringVCType is the type for status list VC.
	// 	status list VC > Type
	StatusListBitstringVCType = "BitstringStatusListCredential"

	// StatusListBitstringEntryType is the subject type of status list entry.
	// 	status list entry VC > Type
	StatusListBitstringEntryType = "BitstringStatusListEntry"

	// StatusListBitstringVCSubjectType is the subject type of status list VC.
	// 	status list VC > Subject > Type
	StatusListBitstringVCSubjectType = "BitstringStatusList"
)

// BitstringStatusListProcessor implements the Bitstring Status List Entry.
// Spec: https://www.w3.org/TR/vc-bitstring-status-list/
type BitstringStatusListProcessor struct {
	*statusListProcessor
}

// NewBitstringStatusListProcessor returns new BitstringStatusListProcessor.
func NewBitstringStatusListProcessor() *BitstringStatusListProcessor {
	return &BitstringStatusListProcessor{
		statusListProcessor: &statusListProcessor{
			statusType:        StatusListBitstringVCSubjectType,
			multibaseEncoding: multibase.Base64url,
		},
	}
}

// GetStatusVCURI returns the ID (URL) of status VC.
func (s *BitstringStatusListProcessor) GetStatusVCURI(vcStatus *verifiable.TypedID) (string, error) {
	statusListVC, ok := vcStatus.CustomFields[StatusListCredential].(string)
	if !ok {
		return "", fmt.Errorf("failed to cast URI of statusListCredential")
	}

	return statusListVC, nil
}

// GetStatusListIndex returns the bit position of the status value of the VC.
func (s *BitstringStatusListProcessor) GetStatusListIndex(vcStatus *verifiable.TypedID) (int, error) {
	index, ok := vcStatus.CustomFields[StatusListIndex].(string)
	if !ok {
		return -1, fmt.Errorf("failed to cast statusListIndex")
	}

	revocationListIndex, err := strconv.Atoi(index)
	if err != nil {
		return -1, fmt.Errorf("unable to get statusListIndex: %w", err)
	}

	return revocationListIndex, nil
}

type statusMessage struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type statusFields struct {
	StatusListCredential string          `json:"statusListCredential"`
	StatusPurpose        string          `json:"statusPurpose"`
	StatusListIndex      string          `json:"statusListIndex"`
	StatusSize           string          `json:"statusSize,omitempty"`
	StatusMessage        []statusMessage `json:"statusMessage,omitempty"`
	StatusReference      string          `json:"statusReference,omitempty"`
}

// ValidateStatus validates the status of vc.
func (s *BitstringStatusListProcessor) ValidateStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return fmt.Errorf("vc status not found")
	}

	if vcStatus.Type != string(StatusListBitstringEntryType) {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	customFieldsBytes, err := json.Marshal(vcStatus.CustomFields)
	if err != nil {
		return fmt.Errorf("failed to marshal custom fields: %w", err)
	}

	fields := &statusFields{}
	if err := json.Unmarshal(customFieldsBytes, fields); err != nil {
		return fmt.Errorf("failed to unmarshal custom fields: %w", err)
	}

	if fields.StatusListIndex == "" {
		return fmt.Errorf("%s field not found in vc status", StatusListIndex)
	}

	if fields.StatusListCredential == "" {
		return fmt.Errorf("%s field not found in vc status", StatusListCredential)
	}

	if fields.StatusPurpose == "" {
		return fmt.Errorf("%s field not found in vc status", StatusPurpose)
	}

	switch fields.StatusPurpose {
	case StatusPurposeRevocation, StatusPurposeSuspension:
		break
	case StatusPurposeMessage:
		if err := validateStatusMessage(fields); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s is an unsupported statusPurpose", fields.StatusPurpose)
	}

	return nil
}

// CreateVCStatus creates verifiable.TypedID.
func (s *BitstringStatusListProcessor) CreateVCStatus(index, vcID, purpose string,
	additionalFields ...vcapi.Field) *verifiable.TypedID {
	vcStatus := &verifiable.TypedID{
		ID:   uuid.New().URN(),
		Type: StatusListBitstringEntryType,
		CustomFields: verifiable.CustomFields{
			StatusPurpose:        purpose,
			StatusListIndex:      index,
			StatusListCredential: vcID,
		},
	}

	for _, field := range additionalFields {
		vcStatus.CustomFields[field.Key] = field.Value
	}

	customFieldsBytes, err := json.Marshal(vcStatus.CustomFields)
	if err != nil {
		return nil
	}

	fields := &statusFields{}
	if err := json.Unmarshal(customFieldsBytes, fields); err != nil {
		return nil
	}

	return vcStatus
}

// GetVCContext returns VC.Context value appropriate for BitStringStatusList.
func (s *BitstringStatusListProcessor) GetVCContext() string {
	return verifiable.V2ContextURI
}

// CreateVC returns *verifiable.Credential appropriate for BitStringStatusList.
func (s *BitstringStatusListProcessor) CreateVC(vcID string, listSize int,
	profile *vcapi.Signer) (*verifiable.Credential, error) {
	vcc := verifiable.CredentialContents{}

	vcc.Context = vcutil.AppendSignatureTypeContext([]string{verifiable.V2ContextURI}, profile.SignatureType)
	vcc.ID = vcID
	vcc.Types = []string{vcType, StatusListBitstringVCType}
	vcc.Issuer = &verifiable.Issuer{ID: profile.DID}
	vcc.Issued = utiltime.NewTime(time.Now().UTC())

	size := listSize

	if size < bitStringSize {
		size = bitStringSize
	}

	encodeBits, err := bitstring.NewBitString(size, bitstring.WithMultibaseEncoding(multibase.Base64url)).EncodeBits()
	if err != nil {
		return nil, err
	}

	vcc.Subject = toVerifiableSubject(credentialSubject{
		ID:            vcc.ID + "#list",
		Type:          StatusListBitstringVCSubjectType,
		StatusPurpose: StatusPurposeRevocation,
		EncodedList:   encodeBits,
	})

	return verifiable.CreateCredential(vcc, nil)
}

func validateStatusMessage(fields *statusFields) error {
	size := 2

	if fields.StatusSize != "" {
		intSize, err := strconv.Atoi(fields.StatusSize)
		if err != nil {
			return fmt.Errorf("unable to get statusSize: %w", err)
		}

		size = int(math.Pow(2, float64(intSize))) //nolint:mnd
	}

	if len(fields.StatusMessage) != size {
		return fmt.Errorf("statusMessage array size must be %d", size)
	}

	for _, message := range fields.StatusMessage {
		if message.Message == "" {
			return fmt.Errorf("message field not found")
		}

		if message.Status == "" {
			return fmt.Errorf("status field not found")
		}

		if len(message.Status) < 3 || message.Status[0:2] != "0x" {
			return fmt.Errorf("status field must be a hex string")
		}
	}

	return nil
}
