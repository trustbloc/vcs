// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/vcs/cmd/vc-rest

require (
	github.com/cenkalti/backoff/v4 v4.1.3
	github.com/deepmap/oapi-codegen v1.11.0
	github.com/google/tink/go v1.6.1
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.9-0.20220911073828-9fc7486e88a9
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20220428163625-96d8261511e1
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20220728172020-0a8903e45149
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20220330151152-6bbd64bde42e
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v1.0.0-rc2.0.20220811162145-47649b185a56
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20220526205258-18d510d84955
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20220728221432-bc126d50cdf9
	github.com/labstack/echo/v4 v4.8.0
	github.com/ory/dockertest/v3 v3.8.1
	github.com/piprate/json-gold v0.4.1
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.3.0
	github.com/stretchr/testify v1.7.2
	github.com/trustbloc/edge-core v0.1.9-0.20220718150010-aa7941986372
	github.com/trustbloc/vcs v0.0.0-00010101000000-000000000000
	go.mongodb.org/mongo-driver v1.10.1
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/PaesslerAG/gval v1.2.0 // indirect
	github.com/PaesslerAG/jsonpath v0.1.1 // indirect
	github.com/VictoriaMetrics/fastcache v1.5.7 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bluele/gcache v0.0.2 // indirect
	github.com/btcsuite/btcd v0.22.0-beta // indirect
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/cli v20.10.11+incompatible // indirect
	github.com/docker/docker v20.10.7+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/evanphx/json-patch v4.1.0+incompatible // indirect
	github.com/fxamacker/cbor/v2 v2.3.0 // indirect
	github.com/getkin/kin-openapi v0.94.0 // indirect
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32 // indirect
	github.com/go-kivik/couchdb/v3 v3.2.8 // indirect
	github.com/go-kivik/kivik/v3 v3.2.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/swag v0.21.1 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.1.2-0.20210512142713-bed466244fa6 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/trillian v1.3.14-0.20210520152752-ceda464a95a3 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v1.0.0-rc2.0.20220729203359-da1de2fa21ce // indirect
	github.com/hyperledger/ursa-wrapper-go v0.3.1 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/ipfs/go-cid v0.0.7 // indirect
	github.com/jinzhu/copier v0.3.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/kawamuray/jsonpath v0.0.0-20201211160320-7483bafabd7e // indirect
	github.com/kilic/bls12-381 v0.1.1-0.20210503002446-7b7597926c69 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/klauspost/cpuid/v2 v2.0.4 // indirect
	github.com/labstack/gommon v0.3.1 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/montanaflynn/stats v0.6.6 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.0.4 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.0.3 // indirect
	github.com/multiformats/go-multihash v0.0.14 // indirect
	github.com/multiformats/go-varint v0.0.6 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799 // indirect
	github.com/opencontainers/runc v1.1.1 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/prometheus/client_golang v1.11.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.26.0 // indirect
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693 // indirect
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	github.com/tidwall/gjson v1.6.7 // indirect
	github.com/tidwall/match v1.0.3 // indirect
	github.com/tidwall/pretty v1.0.2 // indirect
	github.com/tidwall/sjson v1.1.4 // indirect
	github.com/trustbloc/orb v1.0.0-rc2.0.20220811160855-64ffb892b32b // indirect
	github.com/trustbloc/sidetree-core-go v1.0.0-rc2.0.20220729143551-6cda4cea3bf5 // indirect
	github.com/trustbloc/vct v1.0.0-rc2 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.1 // indirect
	github.com/xdg-go/stringprep v1.0.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/net v0.0.0-20220513224357-95641704303c // indirect
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4 // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20220411224347-583f2d630306 // indirect
	golang.org/x/xerrors v0.0.0-20220411194840-2f41105eb62f // indirect
	google.golang.org/genproto v0.0.0-20220222213610-43724f9ea8cf // indirect
	google.golang.org/grpc v1.44.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/trustbloc/vcs => ../..

go 1.19
