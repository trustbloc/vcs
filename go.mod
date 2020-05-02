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
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200430232403-b726cc38d018
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.5.1
	github.com/trustbloc/edge-core v0.1.3-0.20200414220734-842cc197e692
	github.com/trustbloc/edv v0.1.3-0.20200430234942-7eed5374c42e
	github.com/trustbloc/trustbloc-did-method v0.0.0-20200502015848-52b7b5d1e9b7
)

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
