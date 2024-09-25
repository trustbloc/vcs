/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statustype

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/verifiable"

	vcapi "github.com/trustbloc/vcs/pkg/doc/vc"
)

func TestGetVCStatusProcessor_StatusList2021VCStatus(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.StatusList2021VCStatus)
	require.NoError(t, err)
	require.NotNil(t, processor)
	require.Equal(t, StatusList2021Context, processor.GetVCContext())
}

func TestGetVCStatusProcessor_BitstringStatusListEntry(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.BitstringStatusList)
	require.NoError(t, err)
	require.NotNil(t, processor)
	require.Equal(t, verifiable.V2ContextURI, processor.GetVCContext())
}

func TestGetVCStatusProcessor_RevocationList2021VCStatus(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.RevocationList2021VCStatus)
	require.NoError(t, err)
	require.NotNil(t, processor)
	require.Equal(t, RevocationList2021Context, processor.GetVCContext())
}

func TestGetVCStatusProcessor_RevocationList2020VCStatus(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.RevocationList2020VCStatus)
	require.NoError(t, err)
	require.NotNil(t, processor)
	require.Equal(t, RevocationList2020Context, processor.GetVCContext())
}

func TestGetVCStatusProcessor_UnsupportedVCStatusListType(t *testing.T) {
	processor, err := GetVCStatusProcessor(vcapi.StatusType("unsupported"))
	require.Error(t, err)
	require.Nil(t, processor)
	require.Contains(t, err.Error(), "unsupported VCStatusListType")
}
