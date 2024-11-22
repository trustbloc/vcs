/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statustype

import (
	"fmt"

	"github.com/multiformats/go-multibase"
	"github.com/trustbloc/vc-go/verifiable"

	vcapi "github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
)

const (
	jsonFieldStatusListType = "type"
	jsonFieldEncodedList    = "encodedList"
)

// GetVCStatusProcessor returns statustype.StatusProcessor.
func GetVCStatusProcessor(vcStatusListType vcapi.StatusType) (vcapi.StatusProcessor, error) {
	switch vcStatusListType {
	case vcapi.StatusList2021VCStatus, StatusList2021VCSubjectType:
		return NewStatusList2021Processor(), nil
	case vcapi.BitstringStatusList, StatusListBitstringVCSubjectType:
		return NewBitstringStatusListProcessor(), nil
	case vcapi.RevocationList2021VCStatus, revocationList2021VCSubjectType:
		return NewRevocationList2021Processor(), nil
	case vcapi.RevocationList2020VCStatus, revocationList2020VCSubjectType:
		return NewRevocationList2020Processor(), nil
	default:
		return nil, fmt.Errorf("unsupported VCStatusListType %s", vcStatusListType)
	}
}

type statusListProcessor struct {
	statusType        vcapi.StatusType
	multibaseEncoding multibase.Encoding
}

func (p *statusListProcessor) UpdateStatus(
	vc *verifiable.Credential,
	status bool,
	indexes ...int,
) (*verifiable.Credential, error) {
	credSubject := vc.Contents().Subject

	if err := p.validateSubject(credSubject); err != nil {
		return nil, err
	}

	bitString, err := p.getBitstring(&credSubject[0])
	if err != nil {
		return nil, err
	}

	for _, index := range indexes {
		if errSet := bitString.Set(index, status); errSet != nil {
			return nil, fmt.Errorf("bitString.Set failed: %w", errSet)
		}
	}

	credSubject[0].CustomFields[jsonFieldEncodedList], err = bitString.EncodeBits()
	if err != nil {
		return nil, fmt.Errorf("bitString.EncodeBits failed: %w", err)
	}

	return vc.WithModifiedSubject(credSubject), nil
}

func (p *statusListProcessor) IsSet(vc *verifiable.Credential, index int) (bool, error) {
	credSubject := vc.Contents().Subject

	if err := p.validateSubject(credSubject); err != nil {
		return false, err
	}

	bitString, err := p.getBitstring(&credSubject[0])
	if err != nil {
		return false, err
	}

	bitSet, err := bitString.Get(index)
	if err != nil {
		return false, fmt.Errorf("failed to get bit: %w", err)
	}

	return bitSet, nil
}

func (p *statusListProcessor) getBitstring(subject *verifiable.Subject) (*bitstring.BitString, error) {
	encodedList, err := getStringValue(jsonFieldEncodedList, subject.CustomFields)
	if err != nil {
		return nil, fmt.Errorf("failed to get encodedList: %w", err)
	}

	bitString, err := bitstring.DecodeBits(encodedList, bitstring.WithMultibaseEncoding(p.multibaseEncoding))
	if err != nil {
		return nil, fmt.Errorf("failed to decode encodedList: %w", err)
	}

	return bitString, nil
}

func (p *statusListProcessor) validateSubject(subject []verifiable.Subject) error {
	if len(subject) == 0 {
		return fmt.Errorf("invalid subject field structure")
	}

	statusType, err := getStringValue(jsonFieldStatusListType, subject[0].CustomFields)
	if err != nil {
		return fmt.Errorf("failed to get status list type: %w", err)
	}

	if vcapi.StatusType(statusType) != p.statusType {
		return fmt.Errorf("unsupported status list type: %s", statusType)
	}

	return nil
}

func getStringValue(key string, vMap map[string]interface{}) (string, error) {
	if val, ok := vMap[key]; ok {
		if s, ok := val.(string); ok {
			return s, nil
		}

		return "", fmt.Errorf("invalid '%s' type", key)
	}

	return "", nil
}
