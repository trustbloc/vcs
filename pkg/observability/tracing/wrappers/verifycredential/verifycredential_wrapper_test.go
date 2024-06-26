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
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/verifycredential"
	nooptracer "go.opentelemetry.io/otel/trace/noop"
)

const testDID = "did:key:abc"

func TestWrapper_VerifyCredential(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().VerifyCredential(gomock.Any(), &verifiable.Credential{}, &verifycredential.Options{}, &profileapi.Verifier{}).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_, err := w.VerifyCredential(context.Background(), &verifiable.Credential{}, &verifycredential.Options{}, &profileapi.Verifier{})
	require.NoError(t, err)
}

func TestWrapper_ValidateCredentialProof(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().ValidateCredentialProof(gomock.Any(), &verifiable.Credential{}, "proofChallenge", "proofDomain", true, false).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	err := w.ValidateCredentialProof(context.Background(), &verifiable.Credential{}, "proofChallenge", "proofDomain", true, false)
	require.NoError(t, err)
}

func TestWrapper_ValidateVCStatus(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().ValidateVCStatus(gomock.Any(), &verifiable.TypedID{}, &verifiable.Issuer{ID: "issuer"}).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	err := w.ValidateVCStatus(context.Background(), &verifiable.TypedID{}, &verifiable.Issuer{ID: "issuer"})
	require.NoError(t, err)
}

func TestWrapper_ValidateLinkedDomain(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().ValidateLinkedDomain(gomock.Any(), testDID).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	err := w.ValidateLinkedDomain(context.Background(), testDID)
	require.NoError(t, err)
}
