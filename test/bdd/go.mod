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
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200414183703-ab951b13327a
	github.com/mr-tron/base58 v1.1.3
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.5.1
	github.com/trustbloc/edge-core v0.1.3-0.20200414165955-488d2227b903
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/sidetree-core-go v0.1.3-0.20200331141546-1d1a08ef4a77
	github.com/trustbloc/trustbloc-did-method v0.0.0-20200414185052-17ef7829f706
)
