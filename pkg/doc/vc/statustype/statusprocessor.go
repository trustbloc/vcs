/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statustype

import (
	"fmt"

	vcapi "github.com/trustbloc/vcs/pkg/doc/vc"
)

// GetVCStatusProcessor returns statustype.StatusProcessor.
func GetVCStatusProcessor(vcStatusListType vcapi.StatusType) (vcapi.StatusProcessor, error) {
	switch vcStatusListType {
	case vcapi.StatusList2021VCStatus:
		return NewStatusList2021Processor(), nil
	case vcapi.BitstringStatusList:
		return NewBitstringStatusListProcessor(), nil
	case vcapi.RevocationList2021VCStatus:
		return NewRevocationList2021Processor(), nil
	case vcapi.RevocationList2020VCStatus:
		return NewRevocationList2020Processor(), nil
	default:
		return nil, fmt.Errorf("unsupported VCStatusListType %s", vcStatusListType)
	}
}
