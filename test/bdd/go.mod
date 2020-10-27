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
	github.com/google/uuid v1.1.1
	github.com/hyperledger/aries-framework-go v0.1.4
	github.com/trustbloc/edge-core v0.1.5-0.20201026212420-22cb30832cd8
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/trustbloc-did-method v0.1.5-0.20201013133524-7c8154bccbd3
	gotest.tools/v3 v3.0.3 // indirect
)

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
