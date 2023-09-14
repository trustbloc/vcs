# Wallet CLI

Wallet CLI is a tool for testing the OIDC4VCI/OIDC4VP protocols to obtain and present Verifiable Credentials.
It emulates the Wallet behavior against VC services.

## Specifications

* [OpenID for Verifiable Credential Issuance (OIDC4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html)
* [OpenID for Verifiable Presentations (OIDC4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

## Build

Run the following commands from the root of the repository to build the wallet-cli:
```bash
$ cd component/wallet-cli
$ go build .
```

## OpenID for Verifiable Credential Issuance (OIDC4VCI) flow

Verifiable Credential is obtained from the Issuer through the OIDC4VCI flow. Once received, the credential is stored in
the Wallet. Therefore, prior to engaging in the OIDC4VCI flow, it's essential to first create a Wallet.

### Creating a Wallet

Wallet can be created using `create` command. The following CLI arguments are supported:
```bash
      --did-key-type string                did key types supported: ED25519,ECDSAP256DER,ECDSAP384DER (default "ED25519")
      --did-method string                  wallet did methods supported: ion,jwk,key (default "ion")
  -h, --help                               help for create
      --leveldb-path string                leveldb path
      --mongodb-connection-string string   mongodb connection string
      --storage-type string                storage types supported: mem,leveldb,mongodb (default "leveldb")
```

Examples:

* Create wallet with default parameters (leveldb storage, ED25519 key type, did:ion method):
```bash
./wallet-cli create --leveldb-path "/mnt/wallet.db"
```

Running the `create` command on an existing Wallet will generate a new DID for the Wallet. However, once a Wallet's DID
key type is set, it cannot be changed. In subsequent operations with the Wallet (e.g. `oidc4vci` and `oidc4vp` commands)
the most recently created DID is used. To select a specific DID, set its index with `--wallet-did-index` argument.

* Create a new did:jwk for existing Wallet:
```bash
./wallet-cli create --leveldb-path "/mnt/wallet.db" --did-method jwk
```

Note: adding `--did-key-type ECDSAP256DER` to the command above will result in error as the Wallet already initialized
with the key type ED25519 (EdDSA signature type).

### Receiving Verifiable Credential using OIDC4VCI exchange protocol

Once the Wallet is created, it can be used to receive Verifiable Credentials from the Issuer. The `oidc4vci` command is
used for this purpose. The following CLI arguments are supported:
```bash
      --client-id string                   vcs oauth2 client
      --credential-format string           supported credential formats: ldp_vc,jwt_vc_json-ld (default "ldp_vc")
      --credential-offer-url string        credential offer url
      --credential-type string             credential type
      --demo-issuer-url string             demo issuer url for downloading qr code automatically
      --discoverable-client-id             enable discoverable client id scheme for dynamic client registration
      --grant-type string                  supported grant types: authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code (default "authorization_code")
  -h, --help                               help for oidc4vci
      --issuer-state string                issuer state in wallet-initiated flow
      --leveldb-path string                leveldb path
      --login string                       user login on issuer IdP
      --mongodb-connection-string string   mongodb connection string
      --password string                    user password on issuer IdP
      --pin string                         pin for pre-authorized code flow
      --qr-code-path string                path to file with qr code
      --redirect-uri string                callback where the authorization code should be sent (default "http://127.0.0.1/callback")
      --scopes strings                     vcs oauth2 scopes (default [openid])
      --storage-type string                storage types supported: mem,leveldb,mongodb (default "leveldb")
      --wallet-did-index int               index of wallet did, if not set the most recently created DID is used (default -1)
```

Examples:

* Receive VC from the Issuer using pre-authorized code flow:
```bash
./wallet-cli oidc4vci --leveldb-path "/mnt/wallet.db" --qr-code-path "/mnt/qr.png" --grant-type urn:ietf:params:oauth:grant-type:pre-authorized_code --credential-type VerifiedEmployee --credential-format jwt_vc_json-ld
```

* Receive VC from the Issuer using authorization code flow:
```bash
./wallet-cli oidc4vci --leveldb-path "/mnt/wallet.db" --qr-code-path "/mnt/qr.png" --grant-type authorization_code --scopes openid --redirect-uri http://127.0.0.1/callback --client-id oidc4vc_client --credential-type PermanentResidentCard --credential-format ldp_vc
```

### Presenting Verifiable Credential using OIDC4VP exchange protocol

Use the `oidc4vp` command to present Verifiable Credential to the Verifier:
```bash
  -h, --help                               help for oidc4vp
      --leveldb-path string                leveldb path
      --linked-domain-verification         enable linked domain verification
      --mongodb-connection-string string   mongodb connection string
      --qr-code-path string                path to file with qr code
      --storage-type string                storage types supported: mem,leveldb,mongodb (default "leveldb")
      --wallet-did-index int               index of wallet did, if not set the most recently created DID is used (default -1)
```

Examples:

* Present VC to the Verifier with enabled linked domain verification:
```bash
./wallet-cli oidc4vp --leveldb-path "/mnt/wallet.db" --qr-code-path "/mnt/qr.png" --linked-domain-verification
```

## Contributing

We appreciate your help! For contributors, please follow our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md)
to understand our code of conduct and the process for submitting pull requests.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
