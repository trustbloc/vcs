// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/google/tink/go v1.5.0
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20201222220949-494657120ff6
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5
	github.com/trustbloc/edv v0.1.5
	github.com/trustbloc/trustbloc-did-method v0.1.5
)

replace github.com/trustbloc/edge-core => github.com/trustbloc/edge-core v0.1.5-0.20201126210935-53388acb41fc
