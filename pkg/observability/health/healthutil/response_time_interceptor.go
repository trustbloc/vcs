/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthutil

import (
	"context"
	"sync"
	"time"

	"github.com/alexliesenfeld/health"
)

type ResponseTimeState struct {
	LastResponseTime    time.Duration
	AverageResponseTime time.Duration
}

func ResponseTimeInterceptor(m map[string]ResponseTimeState) health.Interceptor {
	var mu sync.Mutex
	return func(next health.InterceptorFunc) health.InterceptorFunc {
		return func(ctx context.Context, name string, state health.CheckState) health.CheckState {
			now := time.Now()
			result := next(ctx, name, state)

			elapsed := time.Since(now)

			mu.Lock()
			defer mu.Unlock()

			if _, ok := m[name]; !ok {
				m[name] = ResponseTimeState{
					LastResponseTime:    elapsed,
					AverageResponseTime: elapsed,
				}
			} else {
				m[name] = ResponseTimeState{
					LastResponseTime:    elapsed,
					AverageResponseTime: (m[name].AverageResponseTime + elapsed) / 2, //nolint:mnd
				}
			}

			return result
		}
	}
}
