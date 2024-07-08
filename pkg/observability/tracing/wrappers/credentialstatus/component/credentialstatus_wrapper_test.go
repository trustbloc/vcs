/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	nooptracer "go.opentelemetry.io/otel/trace/noop"
)

const (
	profileID      = "profileID"
	profileVersion = "profileVersion"
	credentialID   = "credentialID"
)

func TestWrapper_CreateStatusListEntry(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().CreateStatusListEntry(
		gomock.Any(), profileID, profileVersion, credentialID).Times(1).Return(nil, nil)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_, err := w.CreateStatusListEntry(context.Background(), profileID, profileVersion, credentialID)
	require.NoError(t, err)
}

func TestWrapper_GetStatusListVC(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().GetStatusListVC(gomock.Any(), profileID, "statusID").Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_, err := w.GetStatusListVC(context.Background(), profileID, "statusID")
	require.NoError(t, err)
}

func TestWrapper_UpdateVCStatus(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().UpdateVCStatus(gomock.Any(), credentialstatus.UpdateVCStatusParams{}).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	err := w.UpdateVCStatus(context.Background(), credentialstatus.UpdateVCStatusParams{})
	require.NoError(t, err)
}

func TestWrapper_StoreIssuedCredentialMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().StoreIssuedCredentialMetadata(gomock.Any(), profileID, profileVersion, gomock.Any()).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	meta := &credentialstatus.CredentialMetadata{CredentialID: credentialID}

	err := w.StoreIssuedCredentialMetadata(context.Background(), profileID, profileVersion, meta)
	require.NoError(t, err)
}

func TestWrapper_Resolve(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().Resolve(gomock.Any(), "statusListVCURI").Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_, err := w.Resolve(context.Background(), "statusListVCURI")
	require.NoError(t, err)
}
