/*CreateStatusListEntry
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package eventhandler

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vcs/pkg/event/spi"
	nooptracer "go.opentelemetry.io/otel/trace/noop"
)

func TestWrapper_HandleEvent(t *testing.T) {
	event := spi.NewEvent(
		"http://example.edu/credentials/1872",
		"test",
		spi.CredentialStatusStatusUpdated)

	ctrl := gomock.NewController(t)

	svc := NewMockEventHandler(ctrl)
	svc.EXPECT().HandleEvent(gomock.Any(), event).Times(1)

	w := Wrap(svc, nooptracer.NewTracerProvider().Tracer(""))

	err := w.HandleEvent(context.Background(), event)
	require.NoError(t, err)
}
