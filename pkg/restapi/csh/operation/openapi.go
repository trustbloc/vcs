/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
)

// Error.
//
// swagger:response Error
type errorResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body openapi.Error
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
	Body openapi.Profile
}

// createQueryReq model
//
// swagger:parameters createQueryReq
type createQueryReq struct { // nolint:deadcode,unused // swagger model
	// in: path
	// required: true
	ProfileID string `json:"profileID"`

	// in: body
	Body openapi.Query
}

// Query.
//
// swagger:response createQueryResp
// TODO - fix swagger polymorpism
type createQueryResp struct { // nolint:deadcode,unused // swagger model
	// in: header
	Location string
	// in: body
	Body openapi.Query
}

// createAuthorizationReq model
//
// swagger:parameters createAuthorizationReq
type createAuthorizationReq struct { // nolint:deadcode,unused // swagger model
	// in: path
	// required: true
	ProfileID string `json:"profileID"`

	// in: body
	Body openapi.Authorization
}

// Authorization.
//
// swagger:response createAuthorizationResp
type createAuthorizationResp struct { // nolint:deadcode,unused // swagger model
	// in: header
	Location string
	// in: body
	Body openapi.Authorization
}

// comparisonReq model
//
// swagger:parameters comparisonReq
type comparisonReq struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body openapi.ComparisonRequest
}

// Comparison.
//
// swagger:response comparisonResp
type comparisonResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body openapi.Comparison
}

// extractionReq model
//
// swagger:parameters extractionReq
type extractionReq struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body []openapi.Query
}

// extractionResp model
//
// swagger:response extractionResp
type extractionResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body []interface{}
}
