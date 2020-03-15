// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/test/bdd

replace github.com/trustbloc/edge-service => ../..

go 1.13

require (
	github.com/cucumber/godog v0.8.1
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200311212058-6f509cae073a
	github.com/sirupsen/logrus v1.4.2
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/trustbloc-did-method v0.0.0-20200315162906-e189c8677579
)
