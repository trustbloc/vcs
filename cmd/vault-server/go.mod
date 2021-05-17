// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vault-server

go 1.16

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210517160459-a72f856f36b8
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210426192704-553740e279e5
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210505173234-006b2f4723fd
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.1.0
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210510053848-903ac6748b72
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210510053848-903ac6748b72
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210517172158-aa11a4f18737
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
)

replace github.com/trustbloc/edge-service => ../..
