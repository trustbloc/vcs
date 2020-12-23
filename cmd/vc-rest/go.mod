// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vc-rest

require (
	github.com/google/tink/go v1.5.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20201222220949-494657120ff6
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20201119153638-fc5d5e680587
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20201119153638-fc5d5e680587
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/edv v0.1.5
	github.com/trustbloc/trustbloc-did-method v0.1.5
)

replace github.com/trustbloc/edge-service => ../..

replace github.com/trustbloc/edge-core => github.com/trustbloc/edge-core v0.1.5-0.20201126210935-53388acb41fc

go 1.15
