/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthutil_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexliesenfeld/health"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/observability/health/healthutil"
)

func TestResultWriter_Write(t *testing.T) {
	writer := healthutil.NewJSONResultWriter(map[string]healthutil.ResponseTimeState{
		"up": {
			LastResponseTime:    time.Millisecond,
			AverageResponseTime: time.Millisecond,
		},
	})

	rw := httptest.NewRecorder()
	now := time.Now()

	err := writer.Write(&health.CheckerResult{
		Status: health.StatusUp,
		Details: &map[string]health.CheckResult{
			"up": {
				Status:    health.StatusUp,
				Timestamp: &now,
			},
			"down": {
				Status:    health.StatusDown,
				Timestamp: &now,
			},
		},
	}, http.StatusOK, rw, nil)

	require.NoError(t, err)
}
