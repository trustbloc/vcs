/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus/versions"
)

// VcStatusProcessor holds the list of methods required for processing different versions of Status(Revocation) List VC.
type VcStatusProcessor interface {
	ValidateStatus(vcStatus *verifiable.TypedID) error
	GetStatusVCURI(vcStatus *verifiable.TypedID) (string, error)
	GetStatusListIndex(vcStatus *verifiable.TypedID) (int, error)
	CreateVC(vcID string, listSize int, profile *vc.Signer) (*verifiable.Credential, error)
	CreateVCStatus(statusListIndex string, vcID string) *verifiable.TypedID
	GetVCContext() string
}

// GetVCStatusProcessor returns VcStatusProcessor.
func GetVCStatusProcessor(vcStatusListVersion vc.StatusVersion) (VcStatusProcessor, error) {
	switch vcStatusListVersion {
	case vc.StatusList2021VCStatus:
		return versions.NewStatusList2021Processor(), nil
	case vc.RevocationList2021VCStatus:
		return versions.NewRevocationList2021Processor(), nil
	case vc.RevocationList2020VCStatus:
		return versions.NewRevocationList2020Processor(), nil
	default:
		return nil, fmt.Errorf("unsupported VCStatusListVersion %s", vcStatusListVersion)
	}
}
