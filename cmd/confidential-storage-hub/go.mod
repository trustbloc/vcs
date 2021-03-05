// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/confidential-storage-hub

go 1.15

require (
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210305153131-b589754fe1e7
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210305153131-b589754fe1e7
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210304151911-954ad69796fc
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edv v0.1.6-0.20210212224738-ec2041a015c9
)

replace github.com/trustbloc/edge-service => ../..
