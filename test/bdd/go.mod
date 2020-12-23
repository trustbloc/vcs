// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/test/bdd

replace github.com/trustbloc/edge-service => ../..

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/cucumber/godog v0.8.1
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.6-0.20201222220949-494657120ff6
	github.com/trustbloc/edge-core v0.1.5
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/trustbloc-did-method v0.1.5
	gotest.tools/v3 v3.0.3 // indirect
)

// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
