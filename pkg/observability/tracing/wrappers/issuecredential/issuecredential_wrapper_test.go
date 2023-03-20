/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package issuecredential

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/profile"
)

func TestWrapper_IssueCredential(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().IssueCredential(gomock.Any(), &verifiable.Credential{}, []crypto.SigningOpts{}, &profile.Issuer{}).Times(1)

	w := Wrap(svc, trace.NewNoopTracerProvider().Tracer(""))

	_, err := w.IssueCredential(context.Background(), &verifiable.Credential{}, []crypto.SigningOpts{}, &profile.Issuer{})
	require.NoError(t, err)
}
