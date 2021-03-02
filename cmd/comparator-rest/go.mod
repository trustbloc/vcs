// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/comparator-rest

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210302111730-b1b076db898f
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210227073053-5d4fd6ad6b43
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210226200741-0eb54a9fc74f
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210125133828-10c25f5d6d37
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210225161605-5a3ea609e830
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210227013717-0ea0a23d87d3
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210226125453-b9a45cad81f5
	github.com/trustbloc/edge-service v0.1.5
)

replace github.com/trustbloc/edge-service => ../..
