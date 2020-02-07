// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/test/bdd

replace github.com/trustbloc/edge-service => ../..

go 1.13

require (
	github.com/DATA-DOG/godog v0.7.13
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.2-0.20200207205413-60aad0156610
	github.com/sirupsen/logrus v1.4.2
	github.com/trustbloc/edge-service v0.0.0-20200128165511-06e0a3c3913e
)
