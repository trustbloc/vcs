// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/confidential-storage-hub

go 1.16

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210915134807-3e19121646a4
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210910143505-343c246c837c
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edv v0.1.7
)

replace github.com/trustbloc/edge-service => ../..
