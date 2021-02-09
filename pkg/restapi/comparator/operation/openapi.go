/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"
)

// Error.
//
// swagger:response Error
type errorResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body http.ErrorResponse
}

// createAuthzReq model.
//
// swagger:parameters createAuthzReq
type createAuthzReq struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body Authorization
}

// createAuthorizationResp model.
//
// swagger:response createAuthorizationResp
type createAuthorizationResp struct { // nolint:deadcode,unused // swagger model
	// in: header
	Location string
	// in: body
	Body Authorization
}

// compareReq model.
//
// swagger:parameters compareReq
type compareReq struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body struct {
		OP Operator `json:"op"`
	}
}

// comparisonResp model.
//
// swagger:response comparisonResp
type comparisonResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body Comparison
}

// extractReq model.
//
// swagger:parameters extractReq
type extractReq struct { // nolint:deadcode,unused // swagger model
	// Resource identifier.
	//
	// in: query
	AuthTokens []string `json:"authTokens"`
}

// extractionResp model.
//
// swagger:response extractionResp
type extractionResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body struct{}
}

// configReq model.
//
// swagger:parameters configReq
type configReq struct{} // nolint:deadcode,unused // swagger model

// configResp model.
//
// swagger:response configResp
type configResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body ComparatorConfig
}
