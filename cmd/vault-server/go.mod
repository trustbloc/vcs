// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vault-server

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210211215024-e3eafce4d8d5
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20201119153638-fc5d5e680587
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20201119153638-fc5d5e680587
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.6-0.20210127161542-9e174750f523
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
)

replace github.com/trustbloc/edge-service => ../..
