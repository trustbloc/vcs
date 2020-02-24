// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vc-rest

replace github.com/trustbloc/edge-service => ../..

require (
	github.com/gorilla/mux v1.7.3
	github.com/hyperledger/aries-framework-go v0.1.2-0.20200224205618-566f349b1cee
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/stretchr/testify v1.4.0
	github.com/trustbloc/edge-core v0.1.2-0.20200224194621-9b39cfa7fb77
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/edv v0.1.2-0.20200221145649-344b0ac87c80
)

go 1.13
