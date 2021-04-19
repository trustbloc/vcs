// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service

go 1.15

require (
	github.com/PaesslerAG/gval v1.1.0
	github.com/PaesslerAG/jsonpath v0.1.1
	github.com/btcsuite/btcutil v1.0.2
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/go-openapi/errors v0.20.0
	github.com/go-openapi/runtime v0.19.26
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.14
	github.com/go-openapi/validate v0.20.2
	github.com/google/tink/go v1.5.0
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210330153939-7ec3a2c4697c
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210326155331-14f4ca7d75cb
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210326155331-14f4ca7d75cb
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210415184514-aa162c522bc1
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210413155718-eeb5b3c708be
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210330153939-7ec3a2c4697c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210330153939-7ec3a2c4697c
	github.com/igor-pavlenko/httpsignatures-go v0.0.23
	github.com/spf13/cobra v1.1.3
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210331113925-b13dedfe75eb
	github.com/trustbloc/edv v0.1.7-0.20210420141323-971877b36098
	github.com/trustbloc/kms v0.1.7-0.20210420100919-6aeea555441f
	github.com/trustbloc/trustbloc-did-method v0.1.7-0.20210331120333-aacd187d2f94
)

replace github.com/kilic/bls12-381 => github.com/kilic/bls12-381 v0.0.0-20201104083100-a288617c07f1
