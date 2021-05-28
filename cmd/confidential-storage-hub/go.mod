// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/confidential-storage-hub

go 1.16

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210526123422-eec182deab9a
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.1.1
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210520055214-ae429bb89bf7
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210527163745-994ae929f957
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edv v0.1.7-0.20210527173439-3b17690a0345
)

replace github.com/trustbloc/edge-service => ../..
