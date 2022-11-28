/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"fmt"

	"github.com/trustbloc/vcs/component/credentialstatus/statustype"
	"github.com/trustbloc/vcs/pkg/doc/vc"
)

// GetVCStatusProcessor returns VcStatusProcessor.
func GetVCStatusProcessor(vcStatusListType vc.StatusType) (vc.StatusProcessor, error) {
	switch vcStatusListType {
	case vc.StatusList2021VCStatus:
		return statustype.NewStatusList2021Processor(), nil
	case vc.RevocationList2021VCStatus:
		return statustype.NewRevocationList2021Processor(), nil
	case vc.RevocationList2020VCStatus:
		return statustype.NewRevocationList2020Processor(), nil
	default:
		return nil, fmt.Errorf("unsupported VCStatusListType %s", vcStatusListType)
	}
}
