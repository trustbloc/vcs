// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vc-rest

replace github.com/trustbloc/edge-service => ../..

require (
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200306222945-c921059e0e9d
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.4.0
	github.com/trustbloc/bloc-did-method v0.0.0-20200310192857-ca66f03621f2
	github.com/trustbloc/edge-core v0.1.2
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/edv v0.1.2
)

go 1.13
