// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/test/bdd

replace github.com/trustbloc/edge-service => ../..

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.2
	github.com/cucumber/godog v0.8.1
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/go-openapi/runtime v0.19.26
	github.com/go-openapi/strfmt v0.20.0
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210330153939-7ec3a2c4697c
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210330163233-9482b4291d8e
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210331105523-60637a465684
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210330153939-7ec3a2c4697c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210330153939-7ec3a2c4697c
	github.com/igor-pavlenko/httpsignatures-go v0.0.23
	github.com/tidwall/gjson v1.6.7
	github.com/trustbloc/edge-core v0.1.7-0.20210331113925-b13dedfe75eb
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edv v0.1.7-0.20210310153759-93231203a6e5
	github.com/trustbloc/kms v0.1.7-0.20210331122255-0fc8b8988221
	gotest.tools/v3 v3.0.3 // indirect
)

// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
