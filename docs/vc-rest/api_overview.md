# REST API ENDPOINTS 

This document provides high level overview of VC REST Services. For more details, refer [OpenAPI spec](openapi_demo.md).

## Issuer mode
### 1. Create issuer profile  - POST /profile
Mandatory fields: 
 - name : profile name (example TD etc)
 - [uri](https://www.w3.org/TR/vc-data-model/#dfn-uri) 
 - signatureType

#### Request 
```
{
   "name":"<issuerName>",
   "did":"did:peer:22",
   "uri":"https://example.com/credentials",
   "signatureType":"Ed25519Signature2018",
   "creator":"did:peer:22#key1"
}
```

#### Response
```
{
   "name":"<issuerName>",
   "did":"did:peer:22",
   "uri":"https://example.com/credentials",
   "signatureType":"Ed25519Signature2018",
   "creator":"did:peer:22#key1",
   "created":"010-01-01T19:23:24Z"
}
```

### 2.  Get issuer profile  - GET /profile/{issuerName}

#### Response
```
{
   "name":"<issuerName>",
   "did":"did:peer:22",
   "uri":"https://example.com/credentials",
   "signatureType":"Ed25519Signature2018",
   "creator":"did:peer:22#key1"
}
```

### 3. Delete issuer profile  - DELETE /profile/{issuerName}

#### Response
```
Status 200 OK
```

### 4. Issue Verifiable Credential - POST /{profile}/credentials/issueCredential
Path:
- profile : name of the profile as created in section 1. 

Mandatory fields: 
- [Types](https://www.w3.org/TR/vc-data-model/#types)
- [CredentialSubject](https://www.w3.org/TR/vc-data-model/#credential-subject)

Refer W3C [Issue Credential API](https://w3c-ccg.github.io/vc-issuer-http-api/index.html#/internal/issueCredential) for more info.

#### Request 
```
{
   "credential":{
      "@context":[
         "https://www.w3.org/2018/credentials/v1"
      ],
      "id":"http://example.edu/credentials/1872",
      "type":"VerifiableCredential",
      "credentialSubject":{
         "id":"did:example:ebfeb1f712ebc6f1c276e12ec21"
      },
      "issuer":{
         "id":"did:example:76e12ec712ebc6f1c221ebfeb1f",
         "name":"Example University"
      },
      "issuanceDate":"2010-01-01T19:23:24Z",
      "credentialStatus": {
          "id": "https://example.gov/status/24#94567",
          "type": "RevocationList2020Status",
          "revocationListIndex": "94567",
          "revocationListCredential": "https://example.gov/status/24"
      }
   },
   "options":{
      "assertionMethod":"did:trustbloc:testnet.trustbloc.local:EiAiijiRNEAflOr6ZOJN5A7BCFQD1pwFMI1MPzHr3bXezg=="
   }
}
```

#### Response
```
{
   "@context":[
      "https://www.w3.org/2018/credentials/v1"
   ],
   "credentialSchema":[

   ],
   "credentialStatus": {
      "id": "http://issuer.vc.rest.example.com:8070/status/1#94567",
      "type": "RevocationList2020Status",
      "revocationListIndex": "94567",
      "revocationListCredential": "http://issuer.vc.rest.example.com:8070/status/1"
   },
   "credentialSubject":{
      "id":"did:example:ebfeb1f712ebc6f1c276e12ec21"
   },
   "id":"http://example.edu/credentials/1872",
   "issuanceDate":"2010-01-01T19:23:24Z",
   "issuer":{
      "id":"did:example:76e12ec712ebc6f1c221ebfeb1f",
      "name":"Example University"
   },
   "proof":{
      "created":"2020-04-09T15:25:17Z",
      "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..vtNS7iGpYZE0JPmTnCzNPohwLnH6bxN51xL2ZVyIn1dxbEgB8xOe1sTFF2utMSZknkykOdV1PYmKgu0FjvLjAA",
      "proofPurpose":"assertionMethod",
      "type":"Ed25519Signature2018",
      "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiAiijiRNEAflOr6ZOJN5A7BCFQD1pwFMI1MPzHr3bXezg==#key-1"
   },
   "type":"VerifiableCredential"
}
```

### 5. Compose and Issue Verifiable Credential - POST /{profile}/credentials/composeAndIssueCredential
Path:
- profile : name of the profile as created in section 1. 

Refer W3C [Compose and Issue Credential API](https://w3c-ccg.github.io/vc-issuer-http-api/index.html#/internal/composeAndIssueCredential) for more info.

#### Request 
```
{
   "issuer":"did:example:uoweu180928901",
   "subject":"did:example:oleh394sqwnlk223823ln",
   "types":[
      "UniversityDegree"
   ],
   "issuanceDate":"2020-03-25T19:38:54.45546Z",
   "expirationDate":"2020-06-25T19:38:54.45546Z",
   "claims":{
      "name":"John Doe"
   },
   "evidence":{
      "id":"http://example.com/policies/credential/4",
      "type":"IssuerPolicy"
   },
   "termsOfUse":{
      "id":"http://example.com/policies/credential/4",
      "type":"IssuerPolicy"
   },
   "proofFormat":"jws",
   "proofFormatOptions":{
      "kid":"did:trustbloc:testnet.trustbloc.local:EiAtPEWAphdPVRxlKpr8N43uyLMhgF-9SFmYfINVpDIzUA==#key-1"
   }
}
```

#### Response
```
{
   "@context":[
      "https://www.w3.org/2018/credentials/v1"
   ],
   "credentialSchema":null,
   "credentialStatus": {
      "id": "http://issuer.vc.rest.example.com:8070/status/1#94567",
      "type": "RevocationList2020Status",
      "revocationListIndex": "94567",
      "revocationListCredential": "http://issuer.vc.rest.example.com:8070/status/1"
   },
   "credentialSubject":{
      "customField":"customFieldVal",
      "id":"did:example:oleh394sqwnlk223823ln",
      "name":"John Doe"
   },
   "evidence":{
      "customField":"customFieldVal",
      "id":"http://example.com/policies/credential/4",
      "type":"IssuerPolicy"
   },
   "expirationDate":"2020-06-25T19:38:54.45546Z",
   "issuanceDate":"2020-03-25T19:38:54.45546Z",
   "issuer":"did:example:uoweu180928901",
   "proof":{
      "created":"2020-04-09T15:30:13Z",
      "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PETccPkJ1rvnU8rsTVLyWGvaK_ahxVbWdXxcnvyPMUNgg2Ks1CkliAk8vEf2B8srxsxn6XVMXeMh0yfbmbLIAg",
      "proofPurpose":"assertionMethod",
      "type":"Ed25519Signature2018",
      "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiAtPEWAphdPVRxlKpr8N43uyLMhgF-9SFmYfINVpDIzUA==#key-1"
   },
   "termsOfUse":{
      "id":"http://example.com/policies/credential/4",
      "type":"IssuerPolicy"
   },
   "type":"UniversityDegree"
}
```

### 6. Store verifiable credential - POST /store

You must create the credential before storing the credential in [EDV](https://github.com/trustbloc/edv)

#### Request 
```
{
   "profile":"issuer",
   "credential":{
      "context":"https://www.w3.org/2018/credentials/examples/v1",
      "type":[
         "VerifiableCredential",
         "UniversityDegreeCredential"
      ],
      "credentialSubject":{
         "id":"did:example:ebfeb1f712ebc6f1c276e12ec21",
         "degree":{
            "type":"BachelorDegree",
            "university":"MIT"
         },
         "name":"Jayden Doe",
         "spouse":"did:example:c276e12ec21ebfeb1f712ebc6f1"
      },
      "id":"https://example.com/credentials/c276e12ec21ebfeb1f712ebc6f1"
   }
}
```

#### Response
```
Status 200 OK
```

### 7. Retrieve verifiable credential - GET  /retrieve?id=https://example.com/credentials/c276e12ec21ebfeb1f712ebc6f1&profile=issuer
- VC ID as created in section 3 
- Profile name as created in section 1

#### Response
```
{
   "context":"https://www.w3.org/2018/credentials/examples/v1",
   "type":[
      "VerifiableCredential",
      "UniversityDegreeCredential"
   ],
   "credentialSubject":{
      "id":"did:example:ebfeb1f712ebc6f1c276e12ec21",
      "degree":{
         "type":"BachelorDegree",
         "university":"MIT"
      },
      "name":"Jayden Doe",
      "spouse":"did:example:c276e12ec21ebfeb1f712ebc6f1"
   },
   "id":"https://example.com/credentials/c276e12ec21ebfeb1f712ebc6f1"
}
```

### 8. Generate Keypai  - GET /kms/generatekeypair

Generates a keypair, stores it in the KMS and returns the public key.

#### Response
```
{
   "publicKey":"PytfctfFh16xHmyYLo9xHUayFefqUzWtVbWeV7bd2P7"
}
```

### 9. Update Credential Status  - GET /updateStatus

Updates the credential status.

#### Request
```
{
  "credentials":[{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1","https://w3id.org/vc-revocation-list-2020/v1"],"credentialStatus":{"id":"http://issuer.vc.rest.example.com:8070/status/1#0","revocationListCredential":"http://issuer.vc.rest.example.com:8070/status/1","revocationListIndex":"0","type":"RevocationList2020Status"},"credentialSubject":{"degree":{"degree":"MIT","type":"BachelorDegree"},"id":"did:example:ebfeb1f712ebc6f1c276e12ec21","name":"Jayden Doe","spouse":"did:example:c276e12ec21ebfeb1f712ebc6f1"},"id":"https://example.com/credentials/a3e3f15e-d1f9-4f7c-9a87-f4e32639a21a","issuanceDate":"2020-03-16T22:37:26.544Z","issuer":{"id":"did:trustbloc:testnet.trustbloc.local:EiBxGt6Zo5Wskiuoo9xfV5ak0UM1rfVvnJsVRwe7v6c7VQ","name":"myprofile_ud_unireg_ed25519_pv"},"proof":{"created":"2021-01-12T11:18:18.458561Z","proofPurpose":"assertionMethod","proofValue":"0FCsNfwENYqkVUzswG1c5YzeVOfcSaES40rnUNgNepoj7tj_yOzuwhcgg8jwAM5vaanvUEdE9TR7ZpINk8k4Cw","type":"Ed25519Signature2018","verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiBxGt6Zo5Wskiuoo9xfV5ak0UM1rfVvnJsVRwe7v6c7VQ#EuUM8b277NDHNsocGZxUBZ0jdPvyZFxyMp3SEVLXIxk"},"type":["VerifiableCredential","UniversityDegreeCredential"]}]
}
```

#### Response
```
Status 200 OK
```

### 10. Retrieve Credential Status  - GET /status/{id}

 Retrieves the credential status.

#### Response
```
{
   "id":"http://issuer.vc.rest.example.com:8070/status/1",
   "description":"",
   "verifiableCredential":[
      "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSchema\":[],\"credentialSubject\":{\"currentStatus\":\"Revoked\",\"statusReason\":\"Disciplinary action\"},\"id\":\"https://example.com/credentials/74f03198-d774-42d6-abf4-3d14d9c368e7\",\"issuanceDate\":\"2020-04-09T15:59:59.431358855Z\",\"issuer\":{\"id\":\"did:trustbloc:testnet.trustbloc.local:EiC4gMEY4jalitUXegZaVkyK5RBcNV7AYTmh4DA6pSfhnQ==\",\"name\":\"myprofile_ud\"},\"proof\":{\"created\":\"2020-04-09T15:59:59Z\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"ekP9rtOoHLcidN9HEjbYzPkBRykNTVGrZO_WqF9ecKsDPSuKc6gxQGIefMSShjIwuu331CaxD--84IY4aZA3Bg\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:trustbloc:testnet.trustbloc.local:EiC4gMEY4jalitUXegZaVkyK5RBcNV7AYTmh4DA6pSfhnQ==#key-1\"},\"type\":\"VerifiableCredential\"}"
   ]
}
```

## Holder mode
### 1. Create Holder profile  - POST /holder/profile
Mandatory fields: 
 - name : holder profile name
#### Request 
```
{
   "name":"<holderName>",
   "signatureType":"Ed25519Signature2018",
   "signatureRepresentation":1,
   "didKeyType":"Ed25519"
}
```

#### Response
```
{
   "name":"<holderName>",
   "did":"did:trustbloc:testnet.trustbloc.local:EiAmRfGoQaIbmL6C1g48r4n9cOuPgyZkXjaaebuIzfpSpA",
   "signatureType":"Ed25519Signature2018",
   "signatureRepresentation":1,
   "creator":"did:trustbloc:testnet.trustbloc.local:EiAmRfGoQaIbmL6C1g48r4n9cOuPgyZkXjaaebuIzfpSpA#bG9jYWwtbG9jazovL2N1c3RvbS9tYXN0ZXIva2V5L2JhRF9lcG1UVTZPTGxGYVhqQ1U4eXM0NmxYa0tTMkZTZURBbUZfWWI0NWc9",
   "didKeyType":"Ed25519",
   "didPrivateKey":"",
   "created":"2020-04-28T19:00:29.806836568Z"
}
```

### 2. Get Holder profile  - GET /holder/profile/{holderName}

#### Response
```
{
   "name":"<holderName>",
   "did":"did:trustbloc:testnet.trustbloc.local:EiAmRfGoQaIbmL6C1g48r4n9cOuPgyZkXjaaebuIzfpSpA",
   "signatureType":"Ed25519Signature2018",
   "signatureRepresentation":1,
   "creator":"did:trustbloc:testnet.trustbloc.local:EiAmRfGoQaIbmL6C1g48r4n9cOuPgyZkXjaaebuIzfpSpA#bG9jYWwtbG9jazovL2N1c3RvbS9tYXN0ZXIva2V5L2JhRF9lcG1UVTZPTGxGYVhqQ1U4eXM0NmxYa0tTMkZTZURBbUZfWWI0NWc9",
   "didKeyType":"Ed25519",
   "didPrivateKey":"",
   "created":"2020-04-28T19:00:29.806836568Z"
}
```

### 3. Delete Holder profile  - DELETE /holder/profile/{holderName}

#### Response
```
Status 200 OK
```

### 4. Sign Presentation  - POST /{profile}/prove/presentations
Path:
- profile: name of the profile as created in section 1. 

Mandatory fields:
- [Presentation](https://www.w3.org/TR/vc-data-model/#presentations-0)

Refer W3C [Prove Presentation API](https://w3c-ccg.github.io/vc-http-api/#/Holder/provePresentation) for more info.

#### Request
```
{
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
}
```

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

## Verifier mode
### 1. Create Verifier profile  - POST /verifier/profile
Mandatory fields:
- id: verifier profile ID
- name: verifier profile name

#### Request
```
{
    "id": "<verifierID>",
    "name": "<verifierName>",
    "credentialChecks": [
        "proof", 
        "status"
    ],
    "presentationChecks": [
        "proof"
    ]
}
```

#### Response
```
{
    "id": "<verifierID>",
    "name": "<verifierName>",
    "credentialChecks": [
        "proof",
        "status"
    ],
    "presentationChecks": [
        "proof"
    ]
}
```

### 2. Get Verifier profile  - GET /verifier/profile/{id}

#### Response
```
{
    "id": "<verifierID>",
    "name": "<verifierName>",
    "credentialChecks": [
        "proof",
        "status"
    ],
    "presentationChecks": [
        "proof"
    ]
}
```

### 3. Delete Verifier profile  - DELETE /verifier/profile/{id}

#### Response
```
Status 200 OK
```

### 4. Verify Credential  - POST {id}/verifier/credentials
Path:
- id : ID of the verifier profile as created in section 1. 

Verifies a credential

Refer W3C [Verify Credential API](https://w3c-ccg.github.io/vc-verifier-http-api/index.html#/internal/verifyCredential) for more info.

#### Request 
```
{
   "verifiableCredential":{
      "@context":[
         "https://www.w3.org/2018/credentials/v1",
         "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "credentialSchema":[

      ],
      "credentialStatus": {
          "id": "http://issuer.vc.rest.example.com:8070/status/1#94567",
          "type": "RevocationList2020Status",
          "revocationListIndex": "94567",
          "revocationListCredential": "http://issuer.vc.rest.example.com:8070/status/1"
      },
      "credentialSubject":{
         "degree":{
            "degree":"MIT",
            "type":"BachelorDegree"
         },
         "id":"did:example:ebfeb1f712ebc6f1c276e12ec21",
         "name":"Jayden Doe",
         "spouse":"did:example:c276e12ec21ebfeb1f712ebc6f1"
      },
      "id":"http://example.gov/credentials/3732",
      "issuanceDate":"2020-03-16T22:37:26.544Z",
      "issuer":{
         "id":"did:example:oakek12as93mas91220dapop092",
         "name":"University"
      },
      "proof":{
         "created":"2020-04-09T15:35:35Z",
         "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kN1srfFqoiejHJwxM8Y0Y9yIonAvFeF2Aoiv6_LTkPqcNXc2rXwT94-uO_PQJbxWJgTD78MvpfCJWsUSRvgCBw",
         "proofPurpose":"assertionMethod",
         "type":"Ed25519Signature2018",
         "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiD3KVRkHAHt6aLO4Kp5PSO3pNhAY_GPZXuKUekVk1uboQ==#key-1"
      },
      "type":[
         "VerifiableCredential",
         "UniversityDegreeCredential"
      ]
   },
   "options":{
      "checks":[
         "proof"
      ]
   }
}
```

#### Response
```
{
   "checks":[
      "proof"
   ]
}
```

### 5. Verify Presentation - POST {id}/verifier/presentations
Path:
- id : ID of the verifier profile as created in section 1. 

Verifies a presentation

Refer W3C [Verify Presentation API](https://w3c-ccg.github.io/vc-verifier-http-api/index.html#/internal/verifyPresentation) for more info.

#### Request 
```
{
   "verifiablePresentation":{
      "@context":[
         "https://www.w3.org/2018/credentials/v1",
         "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "type":[
         "VerifiablePresentation"
      ],
      "verifiableCredential":[
         {
            "@context":[
               "https://www.w3.org/2018/credentials/v1",
               "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "credentialSchema":[

            ],
            "credentialStatus": {
                "id": "http://issuer.vc.rest.example.com:8070/status/1#94567",
                "type": "RevocationList2020Status",
                "revocationListIndex": "94567",
                "revocationListCredential": "http://issuer.vc.rest.example.com:8070/status/1"
            },
            "credentialSubject":{
               "degree":{
                  "degree":"MIT",
                  "type":"BachelorDegree"
               },
               "id":"did:example:ebfeb1f712ebc6f1c276e12ec21",
               "name":"Jayden Doe",
               "spouse":"did:example:c276e12ec21ebfeb1f712ebc6f1"
            },
            "id":"http://example.gov/credentials/3732",
            "issuanceDate":"2020-03-16T22:37:26.544Z",
            "issuer":{
               "id":"did:example:oakek12as93mas91220dapop092",
               "name":"University"
            },
            "proof":{
               "created":"2020-04-09T15:39:15Z",
               "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..zwcgIwZFaHeWKyrfBkrSJuBFFzxM73dbOQFiTqXJ_UDm0EBSFRJxG46G5Fuyzf2BPzzp_SQCeKT-yqBNaz5OCQ",
               "proofPurpose":"assertionMethod",
               "type":"Ed25519Signature2018",
               "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiDmLaaNMDHKqPJJvIXf3ctFT2MGjiUbJpI0AQIti2MjvQ==#key-1"
            },
            "type":[
               "VerifiableCredential",
               "UniversityDegreeCredential"
            ]
         }
      ],
      "proof":{
         "created":"2020-04-09T11:39:17-04:00",
         "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..EHgGkxaBdbu_XpfMEWDcrFoWzvnmOoMChR5Suj46dWRoN9OGZChjhOYBxGF1cEBAJoWdPS0bvqiF3457xxoMDg",
         "proofPurpose":"assertionMethod",
         "type":"Ed25519Signature2018"
      }
   },
   "options":{
      "checks":[
         "proof"
      ]
   }
}
```

#### Response
```
{
   "checks":[
      "proof"
   ]
}
```
