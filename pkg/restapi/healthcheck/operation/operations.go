/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"
	"time"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	commhttp "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"
)

// API endpoints.
const (
	healthCheckEndpoint = "/healthcheck"
)

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
}

// New returns CreateCredential instance.
func New() *Operation {
	return &Operation{}
}

// Operation defines handlers for rp operations.
type Operation struct {
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []support.Handler {
	return []support.Handler{
		support.NewHTTPHandler(healthCheckEndpoint, http.MethodGet, o.healthCheckHandler),
	}
}

func (o *Operation) healthCheckHandler(rw http.ResponseWriter, r *http.Request) {
	resp := &healthCheckResp{
		Status:      "success",
		CurrentTime: time.Now(),
	}

	commhttp.WriteResponse(rw, http.StatusOK, resp)
}
