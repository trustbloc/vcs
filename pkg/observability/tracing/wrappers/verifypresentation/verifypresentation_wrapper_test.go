/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package verifypresentation

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vc-go/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
	nooptracer "go.opentelemetry.io/otel/trace/noop"
)

func TestWrapper_VerifyPresentation(t *testing.T) {
	ctrl := gomock.NewController(t)

	svc := NewMockService(ctrl)
	svc.EXPECT().VerifyPresentation(gomock.Any(), &verifiable.Presentation{}, &verifypresentation.Options{}, &profileapi.Verifier{}).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	_, _, err := w.VerifyPresentation(context.Background(), &verifiable.Presentation{}, &verifypresentation.Options{}, &profileapi.Verifier{})
	require.NoError(t, err)
}
