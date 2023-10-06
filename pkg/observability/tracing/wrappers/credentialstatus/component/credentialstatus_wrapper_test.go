/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	timeutil "github.com/trustbloc/did-go/doc/util/time"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	profileID      = "profileID"
	profileVersion = "profileVersion"
	credentialID   = "credentialID"
)

func TestWrapper_CreateStatusListEntry(t *testing.T) {
	ctrl := gomock.NewController(t)

	credentialMetadata := &credentialstatus.CredentialMetadata{
		CredentialID:   credentialID,
		Issuer:         "testIssuer",
		CredentialType: []string{"verifiableCredential"},
		TransactionID:  uuid.NewString(),
		IssuanceDate:   timeutil.NewTime(time.Now()),
		ExpirationDate: timeutil.NewTime(time.Now().Add(time.Hour)),
	}

	svc := NewMockService(ctrl)
	svc.EXPECT().CreateStatusListEntry(
		gomock.Any(), profileID, profileVersion, credentialMetadata).Times(1).Return(nil, nil)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.CreateStatusListEntry(context.Background(), profileID, profileVersion, credentialMetadata)
	require.NoError(t, err)
}

func TestWrapper_GetStatusListVC(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().GetStatusListVC(gomock.Any(), profileID, "statusID").Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.GetStatusListVC(context.Background(), profileID, "statusID")
	require.NoError(t, err)
}

func TestWrapper_UpdateVCStatus(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().UpdateVCStatus(gomock.Any(), credentialstatus.UpdateVCStatusParams{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	err := w.UpdateVCStatus(context.Background(), credentialstatus.UpdateVCStatusParams{})
	require.NoError(t, err)
}

func TestWrapper_Resolve(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().Resolve(gomock.Any(), "statusListVCURI").Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.Resolve(context.Background(), "statusListVCURI")
	require.NoError(t, err)
}
