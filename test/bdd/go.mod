// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/test/bdd

replace github.com/trustbloc/edge-service => ../..

go 1.13

require (
	github.com/cucumber/godog v0.8.1
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.2-0.20200225143029-d03b175e4bca
	github.com/sirupsen/logrus v1.4.2
	github.com/trustbloc/edge-service v0.0.0-20200128165511-06e0a3c3913e
)
