// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/comparator-rest

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210421205521-3974f6708723
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210326155331-14f4ca7d75cb
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210326155331-14f4ca7d75cb
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210415184514-aa162c522bc1
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210427144858-06fb8b7d2d30
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210422133815-2ef2d99cb692
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210426154540-f9c761ec6943
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
)

replace github.com/trustbloc/edge-service => ../..
