[![Release](https://img.shields.io/github/release/trustbloc/edge-service.svg?style=flat-square)](https://github.com/trustbloc/edge-service/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/edge-service/master/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/edge-service)

[![Build Status](https://dev.azure.com/trustbloc/edge/_apis/build/status/trustbloc.edge-service?branchName=master)](https://dev.azure.com/trustbloc/edge/_build/latest?definitionId=27&branchName=master)
[![codecov](https://codecov.io/gh/trustbloc/edge-service/branch/master/graph/badge.svg)](https://codecov.io/gh/trustbloc/edge-service)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/edge-service)](https://goreportcard.com/report/github.com/trustbloc/edge-service)

## Prerequisites (for running tests and demos)
- Go 1.13
- Docker
- Docker-Compose
- Make

## Targets
```
# run checks and unit tests
make all
# run linter checks
make checks
# run unit tests
make unit-test
```

## Build
To build from source see [here](docs/build.md).

# edge-service

Edge Service is a reference implementation that demonstrates the following story:

Issuer presents the data fetched from CMS, [edge-sandbox](https://github.com/trustbloc/edge-sandbox) for the following
operations: 

- Create issuer profile
- Create verifiable Credential by using [aries-framework-go](https://github.com/hyperledger/aries-framework-go/tree/master/pkg/doc/verifiable) VC parser
- Store verifiable credential in [EDV](https://github.com/trustbloc/edv)
- Retrieve verifiable credential from [EDV](https://github.com/trustbloc/edv)
- Verify verifiable credential 

# Documentation
- [VC REST APIs](docs/vc-rest/api_overview.md)
- [OpenAPI Spec](docs/vc-rest/openapi_spec.md)
- [OpenAPI Demo](docs/vc-rest/openapi_demo.md)
- [VC Interop API Implementation Status](docs/vc-rest/vc_interop_api_impl_status.md)

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/master/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
