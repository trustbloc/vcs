# Confidential Storage Hub

The Confidential Storage Hub enables selective disclosure use cases while acting as a trusted
intermediate component between two or more parties and their
[Confidential Storage](https://identity.foundation/confidential-storage/) vaults.

## How it works

See the [OpenAPI spec](./docs/openapi.yaml).

### Profiles

Users request a profile by specifying a `controller`.

Example request:

```json
{
  "controller": "did:example:123#key-1"
}
```

Example response:

```json
{
  "id": "ueG60yN6UfnynZhF1viH",
  "controller": "did:example:123#key-1",
  "zcap": "jxwVpimImIEUbbgp5Br0"
}
```

### Queries

Users can create query resources for later reference. Queries allow the CSH to read documents stored in Confidential
Storage vaults.

> Note: it is an error to attempt to create a query resource using a `RefQuery`.

Example request:

```jsonc
  {
    "type": "DocQuery",
    "vaultID": "did:example:123",
    "docID": "batphone",
    "path": "$.nxx",         // will select the `nxx` portion of the document for comparison
    "upstreamAuth": {
      "edv": {
        "baseURL": "https://edv.example.com/encrypted-data-vaults",
        "zcap": "QBdo3EdXKaoZUGmGArwe"  // authorization token to use to retrieve the encrypted document
      },
      "kms": {
        "baseURL": "https://kms.example.com",
        "zcap": "giLUqsR1xfU0Qponeji5"  // authorization token used to decrypt the encrypted document
      }
    }
  }
```

The response will contain a `Location` header with the location of the query.

### Comparisons

Users can request comparisons between two or more Confidential Storage documents using different operators.

> Note: only equality is supported for now.

#### Comparison Operators

##### Equality Operator

The `EqOp` operator reports back whether the contents of two or more Confidential Storage documents are equal or not.

> Note: documents are assumed to be JSON documents or JSON values.

Example request:

```jsonc
{
  "type": "EqOp",
  "args": [
    {
      "type": "DocQuery",
      "vaultID": "did:example:123",
      "docID": "batphone",
      "path": "$.nxx",         // will select the `nxx` portion of the document for comparison
      "upstreamAuth": {
        "edv": {
          "baseURL": "https://edv.example.com/encrypted-data-vaults",
          "zcap": "QBdo3EdXKaoZUGmGArwe"  // authorization token to use to retrieve the encrypted document
        },
        "kms": {
          "baseURL": "https://kms.example.com",
          "zcap": "giLUqsR1xfU0Qponeji5"  // authorization token used to decrypt the encrypted document
        }
      }
    },
    {
      "type": "RefQuery",
      "ref": "EN3LFgjs2gVGcVxL1YqZ"  // reference to a query resource
    }
  ]
}
```

### Extractions

Users can request the plaintext extractions of one or more Confidential Storage documents using Query objects.

Example request:

```json
[
  {
    "type": "DocQuery",
    "vaultID": "did:example:123",
    "docID": "batphone",
    "path": "$.nxx",
    "upstreamAuth": {
      "edv": {
        "baseURL": "https://edv.example.com/encrypted-data-vaults",
        "zcap": "QBdo3EdXKaoZUGmGArwe"
      },
      "kms": {
        "baseURL": "https://kms.example.com",
        "zcap": "giLUqsR1xfU0Qponeji5"
      }
    }
  },
  {
    "type": "AuthorizedQuery",
    "authToken": "inaVwUzgcfw5PjyIRmww"
  }
]
```

## Contributing

Thank you for your interest in contributing. Please see our
[community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more
information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](../../LICENSE) file.
