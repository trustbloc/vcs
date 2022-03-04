## Issuer VCS 

The issuer-vcs may be used to issue a W3C Verifiable Credential. 

The first step for integration is to create a a profile at issuer-vcs. Once the issuer has a 
profile at issuer-vcs, then the issuer can invoke issuance APIs to create verifiable credentials. Please 
refer [Issuer tag in OpenAPI spec](../open-api-spec/openAPI.yml) for detailed API docs.

### Example Usage
### Create a Profile
#### Request
```
curl --location --request POST 'https://issuer-vcs.sandbox.trustbloc.dev/profile' \
--header 'Content-Type: application/json' \
--data-raw '{
   "name":"<profileID>",
   "uri":"http://example.com",
   "signatureType":"Ed25519Signature2018",
   "didKeyType":"Ed25519",
   "overwriteIssuer" : true
}'
```

Note: replace `profileID` in the request data  with actual profileID

#### Response
```
{
    "uri": "http://example.com",
    "edvVaultID": "AEPdaFysGdBeQPxwg7SFgp",
    "disableVCStatus": false,
    "overwriteIssuer": false,
    "name": "<profileID>",
    "did": "did:orb:EiAe_HrUlrudtRNYF9PsmS_hjZzTT5Nwza_mYuz7UMPfug",
    "signatureType": "Ed25519Signature2018",
    "signatureRepresentation": 0,
    "creator": "did:orb:EiAe_HrUlrudtRNYF9PsmS_hjZzTT5Nwza_mYuz7UMPfug#5K1YdLPNNQVme2RWfT4OTiHN55fQEfpZEjQJBqNhVeI",
    "created": "2021-08-10T16:30:21.316290126Z"
}
```

### Get Profile data
#### Request
```
curl --location --request GET 'https://issuer-vcs.sandbox.trustbloc.dev/profile/<profileID>'
```

Note: replace `<profileID>` in the path param with actual profileID

#### Response
```
{
    "uri": "http://example.com",
    "edvVaultID": "AEPdaFysGdBeQPxwg7SFgp",
    "disableVCStatus": false,
    "overwriteIssuer": false,
    "name": "<profileID>",
    "did": "did:orb:EiAe_HrUlrudtRNYF9PsmS_hjZzTT5Nwza_mYuz7UMPfug",
    "signatureType": "Ed25519Signature2018",
    "signatureRepresentation": 0,
    "creator": "did:orb:EiAe_HrUlrudtRNYF9PsmS_hjZzTT5Nwza_mYuz7UMPfug#5K1YdLPNNQVme2RWfT4OTiHN55fQEfpZEjQJBqNhVeI",
    "created": "2021-08-10T16:30:21.316290126Z"
}
```


### Issue Credential
#### Request
```
curl --location --request POST 'https://issuer-vcs.sandbox.trustbloc.dev/<profileID>/credentials/issue' \
--header 'Authorization: Bearer vcs_issuer_rw_token' \
--header 'Content-Type: application/json' \
--data-raw '{
    "credential": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
            "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
        ],
        "credentialSubject": {
            "degree": {
                "degree": "Bachelor of Science and Arts",
                "type": "BachelorDegree"
            },
            "id": "did:trustbloc:4vSjd:EiAQcxO7cXUge_EV54by9ehz6KsDXmsRG59fLSsZiUPOJw",
            "name": "Jayden Doe"
        },
        "description": "University Degree Credential for Mr.Jayden Doe",
        "id": "http://example.com/678e0dfd-99db-418f-9fc3-6582f8b18bd0",
        "issuanceDate": "2021-08-10T14:06:39.829544433Z",
        "issuer": {
            "id": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
            "name": "vc-issuer-interop-key"
        },
        "name": "University Degree Credential",
        "type": [
            "VerifiableCredential",
            "UniversityDegreeCredential"
        ]
    }
}'
```

Note: replace `<profileID>` in the path param with actual profileID

#### Response
```
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
        "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
        "https://w3id.org/vc-revocation-list-2020/v1"
    ],
    "credentialStatus": {
        "id": "https://issuer-vcs.sandbox.trustbloc.dev/vc-issuer-test-2/status/1#0",
        "revocationListCredential": "https://issuer-vcs.sandbox.trustbloc.dev/vc-issuer-test-2/status/1",
        "revocationListIndex": "0",
        "type": "RevocationList2020Status"
    },
    "credentialSubject": {
        "degree": {
            "degree": "Bachelor of Science and Arts",
            "type": "BachelorDegree"
        },
        "id": "did:trustbloc:4vSjd:EiAQcxO7cXUge_EV54by9ehz6KsDXmsRG59fLSsZiUPOJw",
        "name": "Jayden Doe"
    },
    "description": "University Degree Credential for Mr.Jayden Doe",
    "id": "http://example.com/678e0dfd-99db-418f-9fc3-6582f8b18bd0",
    "issuanceDate": "2021-08-10T14:06:39.829544433Z",
    "issuer": {
        "id": "did:orb:interim:EiDDXXAh31iiqc4b1xFRRotB9xoioBdmRhlXxpb7ac-u1w",
        "name": "vc-issuer-test-2"
    },
    "name": "University Degree Credential",
    "proof": {
        "created": "2021-08-10T18:23:55.8718307Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "W-jkhiIqwg0j-4vx9nfCgwuh8GIB52CQ1kn3kTlXLqcZ5H7G-3fIOPMLizo5lt-rt7XLBDI_raDJlpf51DsiBw",
        "type": "Ed25519Signature2018",
        "verificationMethod": "did:orb:interim:EiDDXXAh31iiqc4b1xFRRotB9xoioBdmRhlXxpb7ac-u1w#9_BFWpw0fqyeVzKaxSeZ67gRtnfy5Ojri3flX54OL0A"
    },
    "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
    ]
}
```