/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("edge-service-restapi-common-http")

// ErrorResponse to send error message in the response
type ErrorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

// WriteErrorResponse write error resp
func WriteErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(ErrorResponse{
		Message: msg,
	})

	if err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// WriteResponse writes interface value to response
func WriteResponse(rw io.Writer, v interface{}) {
	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		logger.Errorf("Unable to send error response, %s", err)
	}
}
