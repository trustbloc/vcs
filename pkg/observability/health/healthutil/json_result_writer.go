/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthutil

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/alexliesenfeld/health"
)

type healthStatus struct {
	Status     health.AvailabilityStatus `json:"status"`
	Components map[string]checkResult    `json:"components,omitempty"`
}

type checkResult struct {
	health.CheckResult
	LastResponseTime    string `json:"last_response_time,omitempty"`
	AverageResponseTime string `json:"avg_response_time,omitempty"`
}

type JSONResultWriter struct {
	responseTimes map[string]ResponseTimeState
}

func NewJSONResultWriter(m map[string]ResponseTimeState) *JSONResultWriter {
	return &JSONResultWriter{
		responseTimes: m,
	}
}

func (rw *JSONResultWriter) Write(result *health.CheckerResult, status int, w http.ResponseWriter, _ *http.Request) error { //nolint:lll
	r := &healthStatus{Status: result.Status}

	if result.Details != nil {
		r.Components = map[string]checkResult{}
		for name, cr := range result.Details {
			if t, ok := rw.responseTimes[name]; ok {
				r.Components[name] = checkResult{
					CheckResult:         cr,
					LastResponseTime:    t.LastResponseTime.String(),
					AverageResponseTime: t.AverageResponseTime.String(),
				}
			} else {
				r.Components[name] = checkResult{
					CheckResult: cr,
				}
			}
		}
	}

	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("cannot marshal response: %w", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_, err = w.Write(b)
	return err
}
