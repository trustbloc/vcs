/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// changeLogSpecReq model
//
// swagger:parameters changeLogSpecReq
type changeLogSpecReq struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		// The new log specification
		//
		// Required: true
		// Example: edge-service-verifier-restapi=debug:vc-rest=critical:error
		Spec string `json:"spec"`
	}
}

// getLogSpecRes model
//
// swagger:response getLogSpecRes
type getLogSpecRes struct { // nolint: unused,deadcode
	//in: body
	logSpec
}
