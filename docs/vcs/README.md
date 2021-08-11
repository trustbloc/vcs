# TrustBloc Verifiable Credential Services (VCS) 

The TrustBloc Verifiable Credential Services (VCS) project supports following modes based on configurations. The APIs are based on [VC-HTTP-APIs](vc_interop_api_impl_status.md).
- [Issuer](./issuer/README.md) (VC_REST_MODE=issuer)
- [Holder](./holder/README.md) (VC_REST_MODE=holder)
- [Verifier](./verifier/README.md) (VC_REST_MODE=verifier)
- Combined (VC_REST_MODE=combined or not configured) : supports all the above 3 modes

## OpenAPI Spec
- [Generate OpenAPI spec](openapi_spec.md)
- [Run Demo with OpenAPI spec](openapi_demo.md)