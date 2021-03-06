# Comparator

The Comparator serves as an adapter for the [Confidential Storage Hub](../confidential-storage-hub/README.md) (CSH).

It abstracts the lower-level details required to operate the CSH as well as the
[HTTP signature](https://tools.ietf.org/html/draft-cavage-http-signatures-10)
and [ZCAP-LD](https://w3c-ccg.github.io/zcap-ld/) authentication and authorizations schemes
used to protect resources in the CSH, and works in conjunction with the [Vault Server](../vault-server/README.md).

## How it works

See the [OpenAPI spec](./docs/openapi.yaml).

### Authorizations

When a user authorizes a third party to perform a comparison on a Vault Server document:

* An authorization for the CSH to read the document is requested from the Vault Server, resulting authorization tokens
* A "query" resource is configured at the CSH with the authorization tokens, resulting in an opaque handle
* A new authorization token is created allowing the third party to use that opaque handle

### Comparisons

Users can request comparison between two or more Vault Server documents. The result is always either `true` or `false`.

#### Comparison Operators

##### Equality Operator

The `EqOp` operator reports back whether the contents of two or more Vault Server documents are equal or not.
The precise semantics around "equality" are defined by the [Confidential Storage Hub](../confidential-storage-hub/README.md).

Example:

```jsonc
{
  "type": "EqOp",
  "args": [
    {
      "type": "DocQuery",
      "vaultID": "did:example:123",
      "docID": "batphone",
      "docAttrPath": "$.nxx",         // compares an attribute of the document
      "authTokens": {
        "edv": "Ou8DH43g65seMXMhEyW0",
        "kms": "aGV4v8iPqxtGQzZNxV6l"
      }
    },
    {
      "type": "AuthorizedQuery",
      "authToken": "3x44Z7ORNCz7nrRsjnhL"
    }
  ]
}
```

### Extractions

Users can request the plaintext extractions of one or more Vault Server documents using Query objects.

> Note: only `AuthorizedQuery` is suppported at the moment.

Example request:

```json
{
  "queries": [
    {
      "type": "AuthorizedQuery",
      "authToken": "3x44Z7ORNCz7nrRsjnhL"
    },
    {
      "type": "AuthorizedQuery",
      "authToken": "inaVwUzgcfw5PjyIRmww"
    }
  ]
}
```

## Contributing

Thank you for your interest in contributing. Please see our
[community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more
information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](../../LICENSE) file.
