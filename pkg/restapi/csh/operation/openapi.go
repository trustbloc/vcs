/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"

// Error.
//
// swagger:response Error
type errorResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body http.ErrorResponse
}

// createProfileReq model
//
// swagger:parameters createProfileReq
type createProfileReq struct{} // nolint:deadcode,unused // swagger model

// Profile.
//
// swagger:response createProfileResp
type createProfileResp struct { // nolint:deadcode,unused // swagger model
	// in: header
	Location string
	// in: body
	Body Profile
}

// createQueryReq model
//
// swagger:parameters createQueryReq
type createQueryReq struct { // nolint:deadcode,unused // swagger model
	// in: path
	// required: true
	ProfileID string `json:"profileID"`

	// in: body
	Body DocQuery
}

// Query.
//
// swagger:response createQueryResp
// TODO - fix swagger polymorpism
type createQueryResp struct { // nolint:deadcode,unused // swagger model
	// in: header
	Location string
	// in: body
	Body Query
}

// createAuthorizationReq model
//
// swagger:parameters createAuthorizationReq
type createAuthorizationReq struct { // nolint:deadcode,unused // swagger model
	// in: path
	// required: true
	ProfileID string `json:"profileID"`

	// in: body
	Body Authorization
}

// Authorization.
//
// swagger:response createAuthorizationResp
type createAuthorizationResp struct { // nolint:deadcode,unused // swagger model
	// in: header
	Location string
	// in: body
	Body Authorization
}

// comparisonReq model
//
// swagger:parameters comparisonReq
type comparisonReq struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body struct {
		OP Operator `json:"op"`
	}
}

// Comparison.
//
// swagger:response comparisonResp
type comparisonResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body Comparison
}

// extractionReq model
//
// swagger:parameters extractionReq
type extractionReq struct { // nolint:deadcode,unused // swagger model
	// Resource identifier.
	//
	// in: query
	Resource string `json:"resource"`
}

// extractionResp model
//
// swagger:response extractionResp
type extractionResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body struct{}
}
