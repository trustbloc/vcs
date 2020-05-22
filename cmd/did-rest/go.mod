// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/did-rest

require (
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.4-0.20200522110410-cdb66c563096
	github.com/rs/cors v1.7.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.5.1
	github.com/trustbloc/edge-core v0.1.4-0.20200514152520-6eccfe31d648
	github.com/trustbloc/edge-service v0.0.0
)

replace github.com/trustbloc/edge-service => ../..

go 1.13
