## Holder VCS 

The holder-vcs may be used to sign a verifiable presentation. Please 
refer [Holder tag in OpenAPI spec](../open-api-spec/openAPI.yml) for detailed API docs.

### Example Usage
### Create a Profile
#### Request
```
curl --location --request POST 'https://holder-vcs.sandbox.trustbloc.dev/holder/profile' \
--header 'Authorization: Bearer rw_token' \
--header 'Content-Type: application/json' \
--data-raw '{
   "name":"<profileID>",
   "signatureType":"Ed25519Signature2018",
   "didKeyType":"Ed25519"
}'
```

Note: replace `profileID` in the request data  with actual profileID

#### Response
```
{
    "name": "<profileID>",
    "did": "did:orb:interim:EiCEIcqgR-ILYKbT4DX8CrDJDt_nvyI1au7ifI5gC-nOdA",
    "signatureType": "Ed25519Signature2018",
    "signatureRepresentation": 0,
    "creator": "did:orb:interim:EiCEIcqgR-ILYKbT4DX8CrDJDt_nvyI1au7ifI5gC-nOdA#GZUcLlcQmf-o8Ic4YRvBPHmL6DqJ3eyPGtqFW9C6gkc",
    "created": "2021-08-10T19:18:01.528437497Z"
}
```

### Get Profile data
#### Request
```
curl --location --request GET 'https://holder-vcs.sandbox.trustbloc.dev/holder/profile/<profileID>'
```

Note: replace `<profileID>` in the path param with actual profileID

#### Response
```
{
    "name": "<profileID>",
    "did": "did:orb:interim:EiCEIcqgR-ILYKbT4DX8CrDJDt_nvyI1au7ifI5gC-nOdA",
    "signatureType": "Ed25519Signature2018",
    "signatureRepresentation": 0,
    "creator": "did:orb:interim:EiCEIcqgR-ILYKbT4DX8CrDJDt_nvyI1au7ifI5gC-nOdA#GZUcLlcQmf-o8Ic4YRvBPHmL6DqJ3eyPGtqFW9C6gkc",
    "created": "2021-08-10T19:18:01.528437497Z"
}
```

### Generate Presentation
#### Request
```
curl --location --request POST 'https://holder-vcs.sandbox.trustbloc.dev/<profileID>/prove/presentations' \
--header 'Content-Type: application/json' \
--data-raw '{
    "presentation": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
        "type": "VerifiablePresentation",
        "verifiableCredential": [{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
                "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
            ],
            "id": "http://example.edu/credentials/1872",
            "type": "VerifiableCredential",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
            },
            "issuer": {
                "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                "name": "Example University"
            },
            "issuanceDate": "2010-01-01T19:23:24Z",
            "credentialStatus": {
                "id": "https://example.gov/status/24#94567",
                "type": "RevocationList2020Status",
                "revocationListIndex": "94567",
                "revocationListCredential": "https://example.gov/status/24"
            }
        }],
        "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "refreshService": {
            "id": "https://example.edu/refresh/3732",
            "type": "ManualRefreshService2018"
        }
    },
    "options": {
        "authentication": "did:trustbloc:2M5ym:EiBGUoTI02fSsIGkPbwNLfoOjW9JmQkT0XYTdCEwq_r57w#key1"
    }
}'
```

Note: replace `<profileID>` in the path param with actual profileID

#### Response
```
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
    "proof": {
        "created": "2020-11-19T02:03:12.285365946Z",
        "proofPurpose": "authentication",
        "proofValue": "gfdc5gpUNNgYCfaCDlf8-8BeJzDK2mGdbkmozjQ4N5JfghVG7ZDFQKUYhudBoy7x--RVLzywXBZe05_hBptXDA",
        "type": "Ed25519Signature2018",
        "verificationMethod": "did:trustbloc:testnet.trustbloc.local:EiBGUoTI02fSsIGkPbwNLfoOjW9JmQkT0XYTdCEwq_r57w#key1"
    },
    "refreshService": {
        "id": "https://example.edu/refresh/3732",
        "type": "ManualRefreshService2018"
    },
    "type": "VerifiablePresentation",
    "verifiableCredential": [
        {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
                "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
            ],
            "credentialStatus": {
                "id": "https://example.gov/status/24#94567",
                "type": "RevocationList2020Status",
                 "revocationListIndex": "94567",
                "revocationListCredential": "https://example.gov/status/24"
            },
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
            },
            "id": "http://example.edu/credentials/1872",
            "issuanceDate": "2010-01-01T19:23:24Z",
            "issuer": {
                "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                "name": "Example University"
            },
            "type": "VerifiableCredential"
        }
    ]
}
```
