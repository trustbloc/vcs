/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"encoding/json"
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
	rw.Header().Add("Content-Type", "application/json")

	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(ErrorResponse{
		Message: msg,
	})

	if err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// WriteResponse writes interface value to response
func WriteResponse(rw http.ResponseWriter, statusCode int, v interface{}) {
	if v != nil {
		rw.Header().Add("Content-Type", "application/json")
	}

	rw.WriteHeader(statusCode)

	if v != nil {
		err := json.NewEncoder(rw).Encode(v)
		if err != nil {
			logger.Errorf("Unable to send response, %s", err)
		}
	}
}

// WriteResponseBytes writes data bytes to response
func WriteResponseBytes(rw http.ResponseWriter, statusCode int, data []byte) {
	rw.Header().Add("Content-Type", "application/json")

	rw.WriteHeader(statusCode)

	if data != nil {
		_, err := rw.Write(data)
		if err != nil {
			logger.Errorf("Unable to send response, %s", err)
		}
	}
}
