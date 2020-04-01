// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/test/bdd

replace github.com/trustbloc/edge-service => ../..

go 1.13

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/cucumber/godog v0.8.1
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200328075212-b14f446f90bb
	github.com/sirupsen/logrus v1.4.2
	github.com/trustbloc/edge-core v0.1.3-0.20200327203235-d7f232b27a56
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/sidetree-core-go v0.1.3-0.20200329202924-b30de8bf5c8a
	github.com/trustbloc/trustbloc-did-method v0.0.0-20200401180214-c51c8a66c762
)
