// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service

go 1.16

require (
	github.com/PaesslerAG/gval v1.1.0
	github.com/PaesslerAG/jsonpath v0.1.1
	github.com/bluele/gcache v0.0.2 // indirect
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/cenkalti/backoff/v4 v4.1.2
	github.com/go-openapi/errors v0.20.0
	github.com/go-openapi/runtime v0.19.26
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.14
	github.com/go-openapi/validate v0.20.2
	github.com/google/tink/go v1.6.1-0.20210519071714-58be99b3c4d0
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.8-0.20220326012408-071ce8fc905c
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20220325184342-8ccd5c996898
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20220325184342-8ccd5c996898
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20220325184342-8ccd5c996898
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.1.4-0.20220325184342-8ccd5c996898
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20220325184342-8ccd5c996898
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20220326012408-071ce8fc905c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20220326012408-071ce8fc905c
	github.com/igor-pavlenko/httpsignatures-go v0.0.23
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/piprate/json-gold v0.4.1-0.20210813112359-33b90c4ca86c
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/spf13/cobra v1.3.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.8-0.20220324215259-0ab3fd8db3f3
	github.com/trustbloc/edv v0.1.8-0.20220325202420-22e79405724a
)
