# Wallet CLI

Wallet CLI is a tool for testing the OIDC4VCI/OIDC4VP protocols to obtain and present Verifiable Credentials.
It emulates the Wallet behavior against VC services.

## Specifications

* [OpenID for Verifiable Credential Issuance (OIDC4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html)
* [OpenID for Verifiable Presentations (OIDC4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

## Build

Run the following commands from the root of the repository to build the `wallet-cli` executable:
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
      --context-provider-url string        json-ld context provider url
      --did-key-type string                did key types supported: ED25519,ECDSAP256DER,ECDSAP384DER (default "ED25519")
      --did-method string                  wallet did methods supported: ion,jwk,key (default "ion")
  -h, --help                               help for create
      --leveldb-path string                leveldb path
      --mongodb-connection-string string   mongodb connection string
```

Examples:

* Create wallet using `leveldb` storage and default parameters (`ED25519` key type, `did:ion` method):
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

* Create wallet using `mongodb` storage, `did:ion` method and `ECDSAP384DER` key type: 
```bash
./wallet-cli create --mongodb-connection-string "mongodb://localhost:27017" --did-method ion --did-key-type ECDSAP384DER
```

### Receiving Verifiable Credential using OIDC4VCI exchange protocol

Once the Wallet is created, it can be used to receive Verifiable Credentials from the Issuer. The `oidc4vci` command is
used for this purpose. The following CLI arguments are supported:
```bash
      --client-id string                   vcs oauth2 client
      --credential-format string           supported credential formats: ldp_vc,jwt_vc_json-ld (default "ldp_vc")
      --credential-offer string            openid credential offer
      --credential-type string             credential type
      --demo-issuer-url string             demo issuer url for downloading qr code automatically
      --enable-discoverable-client-id      enables discoverable client id scheme for dynamic client registration
      --enable-tracing                     enables http tracing
      --grant-type string                  supported grant types: authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code (default "authorization_code")
  -h, --help                               help for oidc4vci
      --issuer-state string                issuer state in wallet-initiated flow
      --leveldb-path string                leveldb path
      --mongodb-connection-string string   mongodb connection string
      --pin string                         pin for pre-authorized code flow
      --qr-code-path string                path to file with qr code
      --redirect-uri string                callback where the authorization code should be sent (default "http://127.0.0.1/callback")
      --scopes strings                     vcs oauth2 scopes (default [openid])
      --user-login string                  user login on issuer IdP
      --user-password string               user password on issuer IdP
      --wallet-did-index int               index of wallet did, if not set the most recently created DID is used (default -1)
```

Examples:

* Receive VC from the Issuer using `pre-authorized_code` flow:
```bash
./wallet-cli oidc4vci \
--leveldb-path "/mnt/wallet.db" \
--qr-code-path "qr.png" \
--grant-type urn:ietf:params:oauth:grant-type:pre-authorized_code \
--credential-type VerifiedEmployee \
--credential-format jwt_vc_json-ld
```

* Receive VC from the Issuer using `authorization_code` flow:
```bash
./wallet-cli oidc4vci \
--leveldb-path "/mnt/wallet.db" \
--qr-code-path "qr.png" \
--grant-type authorization_code \
--client-id oidc4vc_client \
--credential-type VerifiedEmployee \
--credential-format ldp_vc
```

For the `wallet-initiated` flow, you must include the `--issuer-state` argument. It has the following format: 
https://<gateway>/vcs/oidc/idp/<profile_id>/<profile_version>
```bash
./wallet-cli oidc4vci \
--leveldb-path "/mnt/wallet.db" \
--grant-type authorization_code \
--client-id oidc4vc_client \
--credential-type VerifiedEmployee \
--issuer-state https://<gateway>/vcs/oidc/idp/<profile_id>/<profile_version>
```

For other flows one of `--qr-code-path`, `--credential-offer` or `--demo-issuer-url` is required.

Use `--user-login` and `--user-password` arguments to provide user credentials for the Issuer IdP and skip the login
page in `authorization_code` flow:
```bash
./wallet-cli oidc4vci \
--leveldb-path "/mnt/wallet.db" \
--credential-offer "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fgateway%2Ffdd4f13f-d701-42d4-ad79-898915c25c85.jwt" \
--grant-type authorization_code \
--client-id oidc4vc_client \
--credential-type VerifiedEmployee \
--user-login "<login>" \
--user-password "<password>"
```

To enable HTTP tracing between `wallet-cli` and `vcs`, append the `--enable-tracing` flag to your argument list.

### Presenting Verifiable Credential using OIDC4VP exchange protocol

Use the `oidc4vp` command to present Verifiable Credential to the Verifier:
```bash
      --enable-linked-domain-verification   enables linked domain verification
      --enable-send-all-credentials         enables send all credentials in wallet
      --enable-tracing                      enables http tracing
  -h, --help                                help for oidc4vp
      --leveldb-path string                 leveldb path
      --mongodb-connection-string string    mongodb connection string
      --qr-code-path string                 path to file with qr code
      --wallet-did-index int                index of wallet did, if not set the most recently created DID is used (default -1)
```

Examples:

* Present VC to the Verifier with linked domain verification:
```bash
./wallet-cli oidc4vp --leveldb-path "/mnt/wallet.db" --qr-code-path "qr.png" --enable-linked-domain-verification
```

* Present All VC from wallet to the Verifier:
```bash
./wallet-cli oidc4vp --leveldb-path "/mnt/wallet.db" --qr-code-path "qr.png" --enable-send-all-credentials
```

## Contributing
We appreciate your help! For contributors, please follow our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md)
to understand our code of conduct and the process for submitting pull requests.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
