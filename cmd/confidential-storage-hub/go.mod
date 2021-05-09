// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/confidential-storage-hub

go 1.16

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210429205242-c5e97865879c
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.1.0
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210510053848-903ac6748b72
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210429222332-96b987820e63
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edv v0.1.7-0.20210510134838-bdb20956d60b
)

replace github.com/trustbloc/edge-service => ../..
