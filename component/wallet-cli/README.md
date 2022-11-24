# Wallet CLI

Wallet CLI is a tool for testing the OIDC4VC flows (OIDC4VP and OIDC4CI variations). It simulates the Wallet behavior
against VC services.

## OIDC4VP flow

Check OIDC4VP flow spec [here](https://docs.google.com/document/d/1i-gXCloNjxNUcTS4UijyBcqi7QdpsszutFMxbUYFKKc/edit?pli=1#heading=h.jn2u4w14fq4t).

Referring to the [sequence diagram for OIDC for SIOP presentation](https://drive.google.com/file/d/1AHM3eOYShmVd8EOp-oC1VVmqE8ruNvGU/view)
CLI simulates the Wallet behaviour starting from the step "Scan QR code and loads wallet" (#15) until checking the post authorization response status (#31).

### Prerequisites

During the processing of OIDC4VP flow Wallet has to be enriched with the signed credentials to be able to resolve a Presentation Definition query.
Please refer to the interface ["VCProvider"](pkg/walletrunner/vcprovider/provider.go) that developer may use to provide a different credentials source.
For now there is only one implementation called ["vcs"](pkg/walletrunner/vcprovider/vcs.go) that [by default](pkg/walletrunner/vcprovider/vcs.go)
interacts with the Local VCS API, that can be launched using [BDD docker-compose.yml](../../test/bdd/fixtures/docker-compose.yml) file.

Therefore, to be able to use **vcs** VCProvider with [default VCS local config](pkg/walletrunner/vcprovider/vcs.go), developer should launch [VCS environment](../../test/bdd/fixtures/docker-compose.yml) in advance.

### OIDC4VP command flags

The following CLI arguments are supported for oidc4vp command (./wallet-cli oidc4vp args):

```
`--qrCodePath` - path to the file with QR code. Only `*.gif`, `*.jpg` and `*.png` formats supported.

`--oidc4vpAuthorizationRequest` - OIDC4VP authorization request string. (e.g. `openid-vc://?request_uri=http://example.com/request-object/637b99d5a2a6e0b3fc7d7192`).

`--vcProvider` - VC provider implementation. (Default: `vcs`).

`--vcIssuerURL` - Issuer URL (Default: `https://localhost:4455/issuer/profiles/i_myprofile_ud_es256_jwt/credentials/issue`).

`--vcFormat` - format of the VC. Supported formats are `jwt_vc` and `ldp_vc`. (Default: `jwt_vc`).

Note:

    Either `qrCodePath` or `oidc4vpAuthorizationRequest` must be supplied.
```

### Usage

```bash
# build 
go build -o wallet-cli ./main.go 

#run
./wallet-cli oidc4vp --qrCodePath=testdata/example/qrcode.png
```

### Output example

```bash
$ ./wallet-cli oidc4vp --qrCodePath=qrcode.png
 Start OIDC4VP flow
 AuthorizationRequest: openid-vc://?request_uri=http://vc-rest-echo.trustbloc.local:8075/request-object/637ba60ca2a6e0b3fc7d71a2
 Creating wallet
 Issuing credentials
 Saving credentials to wallet
 4 credentials were saved to wallet
 Fetching request object
 Resolving request object
 Querying VC from wallet
 Creating authorized response
 Sending authorized response
 Credentials shared with verifier
```
