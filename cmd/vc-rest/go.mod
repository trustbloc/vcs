// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vc-rest

replace github.com/trustbloc/edge-service => ../..

require (
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200408183828-f12cbc1b8777
	github.com/rs/cors v1.7.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.5.1
	github.com/trustbloc/edge-core v0.1.3-0.20200327203235-d7f232b27a56
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/edv v0.1.3-0.20200331230259-afb8871c7535
	github.com/trustbloc/trustbloc-did-method v0.0.0-20200408175722-457448ad951b
)

go 1.13
