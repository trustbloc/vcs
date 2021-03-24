// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/comparator-rest

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210324130905-701d7005a14e
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210324103223-38104f9ff716
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210324103223-38104f9ff716
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210324103223-38104f9ff716
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210324130905-701d7005a14e
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210324130905-701d7005a14e
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210324113338-e0047bbbfdff
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
)

replace github.com/trustbloc/edge-service => ../..
