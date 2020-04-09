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
	github.com/google/uuid v1.1.1
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200415150857-2b1d412c850e
	github.com/mr-tron/base58 v1.1.3
	github.com/sirupsen/logrus v1.4.2
	github.com/trustbloc/edge-core v0.1.3-0.20200414220734-842cc197e692
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/sidetree-core-go v0.1.3-0.20200331141546-1d1a08ef4a77
	github.com/trustbloc/trustbloc-did-method v0.0.0-20200416005130-57c6171e5840
)
