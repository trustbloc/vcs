# Vault Server

The Vault Server is an abstraction over
[Confidential Storage](https://identity.foundation/confidential-storage/) vaults and
[WebKMS](https://w3c-ccg.github.io/webkms/) key stores.

## How it works

See the [OpenAPI spec](./docs/openapi.yaml).

### Creating Vaults

When a user creates a vault in the Vault Server:

* a [Decentralized Identifier](https://w3c.github.io/did-core/) is created for the vault
* a WebKMS key store is created with the vault's DID as its controller
* a Confidential Storage vault is created with the vault's DID as its controller

### Storing documents

When a user stores a document in a vault in the Vault Server:

* the user provides a unique identifier for the document and its contents
* the contents are encrypted with a random encryption key
* a new key pair is created in the WebKMS key store
* the encryption key is encrypted by the WebKMS service using the new key pair
* the encrypted artifacts are assembled into an _EncryptedDocument_ and stored in the Confidential Storage
  vault

## Contributing

Thank you for your interest in contributing. Please see our
[community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more
information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](../../LICENSE) file.
