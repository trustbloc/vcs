/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	model.ErrorResponse
}

// governanceProfileRes model
//
// swagger:response governanceProfileRes
type governanceProfileRes struct { // nolint: unused,deadcode
	// in: body
	model.DataProfile
}

// governanceProfileReq model
//
// swagger:parameters governanceProfileReq
type governanceProfileReq struct { // nolint: unused,deadcode
	// in: body
	Params GovernanceProfileRequest
}

// issueGovernanceCredentialReq model
//
// swagger:parameters issueGovernanceCredentialReq
type issueGovernanceCredentialReq struct { // nolint: unused,deadcode
	// profile
	//
	// in: path
	// required: true
	ID string `json:"id"`

	// in: body
	Params IssueCredentialRequest
}

// signPresentationRes model
//
// swagger:response signPresentationRes
type signPresentationRes struct { // nolint: unused,deadcode
	// in: body
}
