// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-service/test/bdd

replace github.com/trustbloc/edge-service => ../..

go 1.16

require (
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/Microsoft/hcsshim v0.8.21 // indirect
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/containerd/containerd v1.5.5 // indirect
	github.com/cucumber/godog v0.9.0
	github.com/docker/docker v20.10.8+incompatible // indirect
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/go-openapi/runtime v0.19.26
	github.com/go-openapi/strfmt v0.20.0
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.8-0.20211209134627-db62fc73a302
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210915134807-3e19121646a4
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210910143505-343c246c837c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210910143505-343c246c837c
	github.com/igor-pavlenko/httpsignatures-go v0.0.23
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/opencontainers/runc v1.0.2 // indirect
	github.com/tidwall/gjson v1.6.7
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/edge-service v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edv v0.1.7
	golang.org/x/sys v0.0.0-20210823070655-63515b42dcdf // indirect
)
