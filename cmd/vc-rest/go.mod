// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vc-rest

require (
	github.com/google/tink/go v0.0.0-20200403150819-3a14bf4b3380
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.4-0.20200528153636-1d4c39e41ae7
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.5.1
	github.com/trustbloc/edge-core v0.1.4-0.20200814194611-5f3b95f18b63
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/edv v0.1.4-0.20200815210630-993f07543815
	github.com/trustbloc/trustbloc-did-method v0.1.4-0.20200811134027-539ff50d182f
)

replace github.com/trustbloc/edge-service => ../..

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

go 1.13
