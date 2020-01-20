// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vc-rest

replace github.com/trustbloc/edge-service => ../..

require (
	github.com/gorilla/mux v1.7.3
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/stretchr/testify v1.4.0
	github.com/trustbloc/edge-core v0.0.0-20200117175518-7997acf8ed7a
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/edv v0.0.0-20200117213234-9e415c572513
)

go 1.13
