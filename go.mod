// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/go-openapi/errors v0.20.0
	github.com/go-openapi/runtime v0.19.26
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.14
	github.com/go-openapi/validate v0.20.2
	github.com/google/tink/go v1.5.0
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210212132055-b94cce120dda
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20201119153638-fc5d5e680587
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20201119153638-fc5d5e680587
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210121210840-ee9984a4579c
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210125133828-10c25f5d6d37
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/spf13/cobra v1.1.1
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210212172534-81ab3a5abf5b
	github.com/trustbloc/edv v0.1.6-0.20210212224738-ec2041a015c9
	github.com/trustbloc/kms v0.1.6-0.20210212190250-8b11dc498eb1
	github.com/trustbloc/trustbloc-did-method v0.1.6-0.20210212224127-9a501ef7b9e3
)
