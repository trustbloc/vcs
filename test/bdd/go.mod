// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/vcs/test/bdd

replace github.com/trustbloc/vcs => ../..

go 1.18

require (
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/cucumber/godog v0.12.5
	github.com/google/uuid v1.3.0
	github.com/hyperledger/aries-framework-go v0.1.9-0.20220617141911-82112d172a78
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v1.0.0-rc.1.0.20220603055629-55b4fab22d40
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20220526205258-18d510d84955
	github.com/tidwall/gjson v1.9.3
	github.com/trustbloc/edge-core v0.1.9-0.20220718150010-aa7941986372
	github.com/trustbloc/vcs v0.0.0-00010101000000-000000000000
)

require (
	github.com/VictoriaMetrics/fastcache v1.5.7 // indirect
	github.com/bluele/gcache v0.0.2 // indirect
	github.com/btcsuite/btcd v0.22.0-beta // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cucumber/gherkin-go/v19 v19.0.3 // indirect
	github.com/cucumber/messages-go/v16 v16.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/docker v20.10.8+incompatible // indirect
	github.com/evanphx/json-patch v4.9.0+incompatible // indirect
	github.com/fxamacker/cbor/v2 v2.3.0 // indirect
	github.com/gofrs/uuid v4.2.0+incompatible // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.1.2-0.20210512142713-bed466244fa6 // indirect
	github.com/google/tink/go v1.6.1 // indirect
	github.com/google/trillian v1.3.14-0.20210520152752-ceda464a95a3 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-memdb v1.3.3 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20220728172020-0a8903e45149 // indirect
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v1.0.0-rc.1.0.20220530114906-35b469518049 // indirect
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20220728221432-bc126d50cdf9 // indirect
	github.com/ipfs/go-cid v0.0.7 // indirect
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a // indirect
	github.com/kilic/bls12-381 v0.1.1-0.20210503002446-7b7597926c69 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/klauspost/cpuid/v2 v2.0.4 // indirect
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/montanaflynn/stats v0.6.6 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.0.4 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.0.3 // indirect
	github.com/multiformats/go-multihash v0.0.14 // indirect
	github.com/multiformats/go-varint v0.0.6 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/piprate/json-gold v0.4.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693 // indirect
	github.com/stretchr/testify v1.7.2 // indirect
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/trustbloc/orb v1.0.0-rc1.0.20220531195220-8fc19d247843 // indirect
	github.com/trustbloc/sidetree-core-go v1.0.0-rc.1.0.20220428193233-a1567c33db3e // indirect
	github.com/trustbloc/vct v1.0.0-rc1.0.20220530071917-3aa4f907b424 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.1 // indirect
	github.com/xdg-go/stringprep v1.0.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a // indirect
	go.mongodb.org/mongo-driver v1.10.0 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/net v0.0.0-20220425223048-2871e0cb64e4 // indirect
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4 // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220222213610-43724f9ea8cf // indirect
	google.golang.org/grpc v1.44.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
