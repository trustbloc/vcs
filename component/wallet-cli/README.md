# Wallet CLI

Wallet CLI is a tool for testing the OIDC4VC\OIDC4CI flows (OIDC4VP and OIDC4CI variations). It simulates the Wallet behavior
against VC services.

## OIDC4CI\OIDC4VC flow

Specifications:
* OIDC4CI - [OpenID for Verifiable Credential Issuance, (Version 1_0-08)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-08.html)
* OIDC4VP - [OpenID for Verifiable Presentations (Version ID1)](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0-ID1.html)

### Prerequisites

During the processing of OIDC4VP flow Wallet has to be enriched with the signed credentials to be able to resolve a Presentation Definition query.
Please refer to the interface ["VCProvider"](pkg/walletrunner/vcprovider/provider.go) that developer may use to provide a different credentials source.
For now there is only one implementation called ["vcs"](pkg/walletrunner/vcprovider/vcs.go) that [by default](pkg/walletrunner/vcprovider/vcs.go)
interacts with the Local VCS API, that can be launched using [BDD docker-compose.yml](../../test/bdd/fixtures/docker-compose.yml) file.

Therefore, to be able to use **vcs** VCProvider with [default VCS local config](pkg/walletrunner/vcprovider/vcs.go), developer should launch [VCS environment](../../test/bdd/fixtures/docker-compose.yml) in advance.

## OIDC4CI subcommand
### OIDC4CI command flags

The following CLI arguments are supported for oidc4ci command (./wallet-cli oidc4ci args):
```bash
      --client-id string                            oauth2 client ID
      --context-provider-url string                 context provider. example: https://static-file-server.stg.trustbloc.dev/ld-contexts.json
      --credential-format string                    credential format
      --credential-type string                      credential type
      --debug                                       enable debug mode
      --demo-issuer-url string                      demo issuer url. will automatically download qrcode
      --did-domain string                           did domain. example: https://orb-1.stg.trustbloc.dev
      --did-method string                           did method, supported: orb,ion. default: orb (default "orb")
      --did-service-auth-token string               did service authorization token. example: tk1
      --grant-type string                           grant type (default "authorization_code")
  -h, --help                                        help for oidc4ci
      --initiate-issuance-url string                initiate issuance url
      --insecure                                    this option allows to skip the verification of ssl\tls
      --login string                                user login email
      --oidc-provider-url string                    oidc provider url. example: https://api-gateway.stg.trustbloc.dev
      --password string                             user login password
      --pin string                                  pre-authorized flow pin
      --qr-code string                              path to file with QR code
      --redirect-uri string                         callback where the authorization code should be sent
      --scope strings                               oauth2 scopes. Can be used to pass credential type
      --storage-provider string                     storage provider. supported: mem,leveldb,mongodb
      --storage-provider-connection-string string   storage provider connection string
      --uni-resolver-url string                     uni resolver url. example: https://did-resolver.stg.trustbloc.dev/1.0/identifiers
      --vc-format string                            vc format [jwt_vc_json|ldp_vc] (default "jwt_vc_json")
      --vc-provider string                          vc provider (default "vcs")
      --wallet-did string                           existing wallet did
      --wallet-did-keyid string                     existing wallet did key id
      --wallet-passphrase string                    existing wallet pass phrase
      --wallet-user-id string                       existing wallet user id
```
#### Pre-authorized code flow 
```bash
./wallet-cli oidc4ci \
--qr-code "/mnt/qrcode.png" \
--grant-type urn:ietf:params:oauth:grant-type:pre-authorized_code \
--credential-type VerifiedEmployee \
--credential-format jwt_vc \
--did-domain https://orb-1.stg.trustbloc.dev \
--did-service-auth-token ADMIN_TOKEN \
--context-provider-url https://static-file-server.stg.trustbloc.dev/ld-contexts.json \
--uni-resolver-url https://did-resolver.stg.trustbloc.dev/1.0/identifiers \
--storage-provider leveldb \
--storage-provider-connection-string "/mnt/wallet.db" \
--did-method ion \
--did-key-type ECDSAP384DER \
--debug
```

#### Authorized code flow
```bash
./wallet-cli oidc4ci \
--qr-code "/mnt/qrcode.png" \
--grant-type authorization_code \
--scope openid,profile \
--redirect-uri http://127.0.0.1/callback \
--client-id oidc4vc_client \
--credential-type VerifiedEmployee \
--credential-format jwt_vc \
--did-domain https://orb-1.stg.trustbloc.dev \
--did-service-auth-token ADMIN_TOKEN \
--context-provider-url https://static-file-server.stg.trustbloc.dev/ld-contexts.json \
--uni-resolver-url https://did-resolver.stg.trustbloc.dev/1.0/identifiers \
--storage-provider leveldb \
--storage-provider-connection-string "/mnt/wallet.db" \
--did-method ion \
--debug
```

Note:
* use `--login "john.smith@example.com"` and `--password "f00B@r"` options to log in and give user's consent automatically
* if no wallet params are specified (wallet-user-id, wallet-passphrase, wallet-did-keyid, wallet-did), a new wallet is created and wallet parameters become available in the command output

## OIDC4VP subcommand
### OIDC4VP command flags

The following CLI arguments are supported for oidc4vp command (./wallet-cli oidc4vp args):
```
      --context-provider-url string                 context provider. example: https://static-file-server.stg.trustbloc.dev/ld-contexts.json
      --did-domain string                           did domain. example: https://orb-1.stg.trustbloc.dev
      --did-key-type string                         did key type. default: ECDSAP384DER (default "ECDSAP384DER")
      --did-method string                           did method, supported: orb,ion. default: orb (default "orb")
      --did-service-auth-token string               did service authorization token. example: tk1
  -h, --help                                        help for oidc4vp
      --insecure                                    this option allows to skip the verification of ssl\tls
      --oidc-client-id string                       oidc client id. example: test-org
      --oidc-client-secret string                   oidc client secret. example: test-org-secret
      --oidc-provider-url string                    oidc provider url. example: https://orb-1.stg.trustbloc.dev
      --oidc4-vp-authorization-request string       OIDC4VP Authorization Request
      --oidc4-vp-should-request-credentials         indicates if oidc4vp flow should request new credentials (default true)
      --qrcode-path string                          Path to QR code file
      --skip-schema-validation                      skip schema validation for while creating vp
      --storage-provider string                     storage provider. supported: mem,leveldb,mongodb
      --storage-provider-connection-string string   storage provider connection string
      --uni-resolver-url string                     uni resolver url. example: https://did-resolver.stg.trustbloc.dev/1.0/identifiers
      --vc-format string                            VC format (jwt_vc_json/ldp_vc) (default "jwt_vc_json")
      --vc-issuer-url string                        VC Issuer URL
      --vc-provider string                          VC Provider (default "vcs")
      --wallet-did string                           existing wallet did
      --wallet-did-keyid string                     existing wallet did key id
      --wallet-passphrase string                    existing wallet pass phrase
      --wallet-user-id string                       existing wallet user id
Note:

    Either `qrcode-path` or `oidc4-vp-authorization-request"` must be supplied.
```

### Usage OIDC4VP
```bash
./wallet-cli oidc4vp \
--qrcode-path "/mnt/qrcode.png" \
--vc-provider vcs \
--vc-issuer-url https://api-gateway.stg.trustbloc.dev/issuer/profiles/bank_issuer/credentials/issue \
--vc-format jwt_vc \
--context-provider-url https://static-file-server.stg.trustbloc.dev/ld-contexts.json \
--did-domain https://orb-1.stg.trustbloc.dev \
--did-service-auth-token ADMIN_TOKEN \
--uni-resolver-url https://did-resolver.stg.trustbloc.dev/1.0/identifiers \
--oidc-provider-url https://auth-hydra.stg.trustbloc.dev \
--oidc-client-id test-org \
--oidc-client-secret test-org-secret \
--skip-schema-validation=true \
--oidc4-vp-should-request-credentials=false \
--storage-provider leveldb \
--storage-provider-connection-string "/mnt/wallet.db" \
--did-method ion \
--did-key-type ECDSAP384DER \
--wallet-passphrase "" \
--wallet-user-id "" \
--wallet-did "" \
--wallet-did-keyid "" 

Note: 
  if you are not specifying the existing wallet using (wallet-user-id,wallet-passphrase,wallet-did-keyid,wallet-did) a new wallet will be automatically created and credentials will be available in the command outpu
```