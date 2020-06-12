// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service

go 1.13

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/google/tink/go v0.0.0-20200403150819-3a14bf4b3380
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.4-0.20200528153636-1d4c39e41ae7
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.5.1
	github.com/trustbloc/edge-core v0.1.4-0.20200603140750-8d89a0084be7
	github.com/trustbloc/edv v0.1.3
	github.com/trustbloc/trustbloc-did-method v0.1.4-0.20200525135153-c9d911ac1bb7
)

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
