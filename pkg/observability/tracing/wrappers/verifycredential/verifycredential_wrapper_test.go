/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package verifycredential

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
)

const testDID = "did:key:abc"

func TestWrapper_VerifyCredential(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().VerifyCredential(gomock.Any(), &verifiable.Credential{}, &verifycredential.Options{}, &profileapi.Verifier{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.VerifyCredential(context.Background(), &verifiable.Credential{}, &verifycredential.Options{}, &profileapi.Verifier{})
	require.NoError(t, err)
}

func TestWrapper_ValidateCredentialProof(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().ValidateCredentialProof(gomock.Any(), []byte(""), "proofChallenge", "proofDomain", true, true).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	err := w.ValidateCredentialProof(context.Background(), []byte(""), "proofChallenge", "proofDomain", true, true)
	require.NoError(t, err)
}

func TestWrapper_ValidateVCStatus(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().ValidateVCStatus(gomock.Any(), &verifiable.TypedID{}, "issuer").Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	err := w.ValidateVCStatus(context.Background(), &verifiable.TypedID{}, "issuer")
	require.NoError(t, err)
}

func TestWrapper_ValidateLinkedDomain(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().ValidateLinkedDomain(gomock.Any(), testDID).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	err := w.ValidateLinkedDomain(context.Background(), testDID)
	require.NoError(t, err)
}
