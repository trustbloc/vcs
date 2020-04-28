# VC Interop API Implementation Status

The TrustBloc VC edge service supports multiple W3C CCG HTTP APIs. This page provides the status of the implementation. For detailed API documentation, refer [TrustBloc VC Service Open API Spec](openapi_demo.md) and also extensions defined by [Transmute API](https://transmute-industries.github.io/vc-http-api).


## Issuer
### Issue Credential API
The edge service implements [W3C Issue Credential API](https://w3c-ccg.github.io/vc-issuer-http-api/index.html#/internal/issueCredential) along 
with the following extra options defined by [Transmute Issue Credential API](https://transmute-industries.github.io/vc-http-api/#/Issuer/issueCredential).
- verificationMethod 
- proofPurpose
- created
- domain
- challenge

### Compose And Issue Credential API
Currently, the edge service implements [W3C Compose And Issue Credential API](https://w3c-ccg.github.io/vc-issuer-http-api/index.html#/internal/composeAndIssueCredential) 
without the [support for templateReference and subjectReference](https://github.com/trustbloc/edge-service/issues/144) query parameters.


## Verifier
### Verify Credential API
The edge service supports [W3C Verify Credential API](https://w3c-ccg.github.io/vc-verifier-http-api/index.html#/internal/verifyCredential) along 
with the following extra options defined by [Transmute Verify Credential API](https://transmute-industries.github.io/vc-http-api/#/Verifier/verifyCredential).
- verificationMethod 
- proofPurpose
- created
- domain
- challenge

### Verify Presentation API
The edge service implements [W3C Verify Presentation API](https://w3c-ccg.github.io/vc-verifier-http-api/index.html#/internal/verifyPresentation) along 
with the following extra options defined by [Transmute Verify Presentation API](https://transmute-industries.github.io/vc-http-api/#/Verifier/verifyPresentation).
- verificationMethod 
- proofPurpose
- created
- domain
- challenge


## Holder
### Sign Presentation
The TrustBloc edge service provides a API to sign the presentation as defined by [Transmute Prove Presentation API](https://transmute-industries.github.io/vc-http-api/#/Holder/provePresentation).
