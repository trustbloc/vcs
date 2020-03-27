// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vc-rest

replace github.com/trustbloc/edge-service => ../..

require (
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200325175154-d18ad2581ed9
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.4.0
	github.com/trustbloc/edge-core v0.1.3-0.20200318193133-ec6c4caf61ae
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/edv v0.1.3-0.20200305035835-69c9f3cb077b
	github.com/trustbloc/trustbloc-did-method v0.0.0-20200325213211-3e48939f5ff3
)

go 1.13
