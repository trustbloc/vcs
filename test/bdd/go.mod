// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/test/bdd

replace github.com/trustbloc/edge-service => ../..

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.2
	github.com/cucumber/godog v0.8.1
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/go-openapi/runtime v0.19.26
	github.com/go-openapi/strfmt v0.20.0
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210303180208-4bb3ae8b32c9
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210121210840-ee9984a4579c
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210125133828-10c25f5d6d37
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210303180208-4bb3ae8b32c9
    github.com/hyperledger/aries-framework-go/spi v0.0.0-20210303180208-4bb3ae8b32c9
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/tidwall/gjson v1.6.7
	github.com/trustbloc/edge-core v0.1.6-0.20210226125453-b9a45cad81f5
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edv v0.1.6-0.20210212224738-ec2041a015c9
	github.com/trustbloc/kms v0.1.6-0.20210302134939-3933de07039b
	gotest.tools/v3 v3.0.3 // indirect
)

// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
