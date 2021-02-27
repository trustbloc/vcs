/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/models"
)

// Error.
//
// swagger:response Error
type errorResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body models.Error
}

// createAuthzReq model.
//
// swagger:parameters createAuthzReq
type createAuthzReq struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body models.Authorization
}

// createAuthorizationResp model.
//
// swagger:response createAuthorizationResp
type createAuthorizationResp struct { // nolint:deadcode,unused // swagger model
	// in: header
	Location string
	// in: body
	Body models.Authorization
}

// compareReq model.
//
// swagger:parameters compareReq
type compareReq struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body models.Comparison
}

// comparisonResp model.
//
// swagger:response comparisonResp
type comparisonResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body models.ComparisonResult
}

// extractReq model.
//
// swagger:parameters extractReq
type extractReq struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body models.Extract
}

// extractionResp model.
//
// swagger:response extractionResp
type extractionResp struct { // nolint:deadcode,unused // swagger model
	// in: body
	Body models.ExtractResp
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
	Body models.Config
}
