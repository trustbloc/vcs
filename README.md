[![Release](https://img.shields.io/github/release/trustbloc/edge-service.svg?style=flat-square)](https://github.com/trustbloc/edge-service/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/edge-service/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/edge-service)

[![Build Status](https://github.com/trustbloc/edge-service/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/trustbloc/edge-service/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/trustbloc/edge-service/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/edge-service)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/edge-service)](https://goreportcard.com/report/github.com/trustbloc/edge-service)

# TrustBloc VCS

TrustBloc Verifiable Credential Service (VCS) project provides following services for [W3C Verifiable Credentials (VC)](https://www.w3.org/TR/vc-data-model/) based on [W3C-CCG VC API](https://w3c-ccg.github.io/vc-api/).
- [Issuer](https://w3c-ccg.github.io/vc-api/#issuing)
- [Verifier](https://w3c-ccg.github.io/vc-api/#verifying) 
- [Holder](https://w3c-ccg.github.io/vc-api/#presenting)

The VCS uses golang packages from [Hyperledger Aries Framework Go]([aries-framework-go](https://github.com/hyperledger/aries-framework-go/tree/main/pkg/doc/verifiable)) for KMS, VC and DID operations.

## Build
To build from source see [here](docs/build.md).

## Documentation
- [VC Services](docs/vcs/README.md)
- [OpenAPI Spec](docs/vc-rest/openapi_spec.md)
- [OpenAPI Demo](docs/vc-rest/openapi_demo.md)
- [VC Interop API Implementation Status](docs/vc-rest/vc_interop_api_impl_status.md)


## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
