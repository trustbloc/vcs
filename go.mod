// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service

go 1.13

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/google/tink/go v1.4.0-rc2.0.20200807212851-52ae9c6679b2
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.4-0.20200828184218-b74fc05533e2
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.4-0.20200814194611-5f3b95f18b63
	github.com/trustbloc/edv v0.1.4-0.20200815210630-993f07543815
	github.com/trustbloc/trustbloc-did-method v0.1.4-0.20200828190828-b0b9c17909bf
)

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
