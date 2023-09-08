[![Release](https://img.shields.io/github/release/trustbloc/vcs.svg?style=flat-square)](https://github.com/trustbloc/vcs/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/vcs/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/vcs)

[![Build Status](https://github.com/trustbloc/vcs/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/trustbloc/vcs/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/trustbloc/vcs/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/vcs)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/vcs)](https://goreportcard.com/report/github.com/trustbloc/vcs)

# TrustBloc VCS

The TrustBloc Verifiable Credential Service (VCS) repo contains APIs to Issue and Verify 
[W3C Verifiable Credentials(VCs)](https://www.w3.org/TR/vc-data-model/) signed using 
[W3C Decentralized Identifiers(DIDs)](https://www.w3.org/TR/did-core/). These APIs are useful for 
the Issuer and Verifier role defined in the [W3C VC Specification](https://www.w3.org/TR/vc-data-model/#ecosystem-overview).

## Specifications

The TrustBloc VCS implements following specifications.
- W3C [Verifiable Credential Data Model (VCDM)](https://www.w3.org/TR/vc-data-model/)
- W3C [Decentralized Identifier (DID)](https://www.w3.org/TR/did-core/)
- OIDF [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
    - Pre Authorization Code flow
    - Authorization Code low
- OIDF [OpenID for Verifiable Presentation](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- DIF [Presentation Exchange](https://identity.foundation/presentation-exchange/)
- DIF [Well Known DID Configuration](https://identity.foundation/.well-known/resources/did-configuration/)

## Build
To build from source see [here](docs/build.md).

## Documentation
- [OpenAPI Spec](https://trustbloc.github.io/vcs/)

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
