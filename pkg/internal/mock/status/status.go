/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package status

import (
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
)

type MockStatusProcessorGetter struct {
	StatusProcessor vc.StatusProcessor
	Err             error
}

func (m *MockStatusProcessorGetter) GetMockStatusProcessor(_ vc.StatusType) (vc.StatusProcessor, error) {
	return m.StatusProcessor, m.Err
}

type MockVCStatusProcessor struct {
	ValidateErr           error
	StatusVCURI           string
	GetStatusVCURIErr     error
	StatusListIndex       int
	GetStatusListIndexErr error
	VC                    *verifiable.Credential
	CreateVCErr           error
	VCStatus              *verifiable.TypedID
	VCContext             string
}

func (m *MockVCStatusProcessor) ValidateStatus(_ *verifiable.TypedID) error {
	return m.ValidateErr
}

func (m *MockVCStatusProcessor) GetStatusVCURI(_ *verifiable.TypedID) (string, error) {
	return m.StatusVCURI, m.GetStatusVCURIErr
}

func (m *MockVCStatusProcessor) GetStatusListIndex(_ *verifiable.TypedID) (int, error) {
	return m.StatusListIndex, m.GetStatusListIndexErr
}

func (m *MockVCStatusProcessor) CreateVC(_ string, _ int, _ *vc.Signer) (*verifiable.Credential, error) {
	return m.VC, m.CreateVCErr
}

func (m *MockVCStatusProcessor) CreateVCStatus(_ string, _ string) *verifiable.TypedID {
	return m.VCStatus
}

func (m *MockVCStatusProcessor) GetVCContext() string {
	return m.VCContext
}
