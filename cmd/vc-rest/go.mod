// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/cmd/vc-rest

require (
	github.com/google/tink/go v1.5.0
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201029183113-1e234a0af6c6
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20201030114218-27cdc521d9fc
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20201030114218-27cdc521d9fc
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5-0.20201026212420-22cb30832cd8
	github.com/trustbloc/edge-service v0.0.0
	github.com/trustbloc/edv v0.1.5-0.20201105191852-41fa23f5df5d
	github.com/trustbloc/trustbloc-did-method v0.1.5-0.20201104140931-a5c42ef6b769
)

replace github.com/trustbloc/edge-service => ../..

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

replace github.com/phoreproject/bls => github.com/trustbloc/bls v0.0.0-20201023141329-a1e218beb89e

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201008080608-ba2e87ef05ef

go 1.15
