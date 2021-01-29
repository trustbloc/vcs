/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	Body http.ErrorResponse
}
