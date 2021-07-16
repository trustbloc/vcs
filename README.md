[![Release](https://img.shields.io/github/release/trustbloc/edge-service.svg?style=flat-square)](https://github.com/trustbloc/edge-service/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/edge-service/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/edge-service)

[![Build Status](https://github.com/trustbloc/edge-service/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/trustbloc/edge-service/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/trustbloc/edge-service/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/edge-service)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/edge-service)](https://goreportcard.com/report/github.com/trustbloc/edge-service)

# edge-service

Edge Service is a reference implementation that demonstrates the following story:

Issuer presents the data fetched from CMS, [edge-sandbox](https://github.com/trustbloc/edge-sandbox) for the following
operations: 

- Create issuer profile
- Create verifiable Credential by using [aries-framework-go](https://github.com/hyperledger/aries-framework-go/tree/main/pkg/doc/verifiable) VC parser
- Store verifiable credential in [EDV](https://github.com/trustbloc/edv)
- Retrieve verifiable credential from [EDV](https://github.com/trustbloc/edv)
- Verify verifiable credential 

## Build
To build from source see [here](docs/build.md).

## Documentation
- [VC REST APIs](docs/vc-rest/api_overview.md)
- [Vault Server](cmd/vault-server/README.md)
- [Comparator](cmd/comparator-rest/README.md)
- [Confidential Storage Hub](cmd/confidential-storage-hub/README.md)
- [OpenAPI Spec](docs/vc-rest/openapi_spec.md)
- [OpenAPI Demo](docs/vc-rest/openapi_demo.md)
- [VC Interop API Implementation Status](docs/vc-rest/vc_interop_api_impl_status.md)

## Services

- [vault-server](./cmd/vault-server/README.md)
- [comparator](./cmd/comparator-rest/README.md)

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
