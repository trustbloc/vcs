/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthutil_test

import (
	"context"
	"testing"

	"github.com/alexliesenfeld/health"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/observability/healthutil"
)

func TestResponseTimeInterceptor(t *testing.T) {
	interceptor := healthutil.ResponseTimeInterceptor(map[string]healthutil.ResponseTimeState{
		"test": {
			LastResponseTime:    0,
			AverageResponseTime: 0,
		},
	})

	next := &mockInterceptor{}

	interceptor(next.InterceptorFunc())(context.Background(), "test", health.CheckState{})

	require.True(t, next.Called)
}

type mockInterceptor struct {
	Called bool
}

func (m *mockInterceptor) InterceptorFunc() health.InterceptorFunc {
	return func(ctx context.Context, name string, state health.CheckState) health.CheckState {
		m.Called = true
		return state
	}
}
