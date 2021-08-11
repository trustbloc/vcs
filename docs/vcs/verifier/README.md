## Verifier VCS 

The verifier-vcs may be used to issue a W3C Verifiable Credential. 

The first step for integration is to create a a profile at verifier-vcs. Once the verifier has a 
profile at verifier-vcs, then the verifier can invoke verification APIs to validate credentials and presentations. Please 
refer [Verifier tag in OpenAPI spec](../open-api-spec/openAPI.yml) for detailed API docs.


### Example Usage
### Create a Profile
#### Request
```
curl --location --request POST 'https://verifier-vcs.sandbox.trustbloc.dev/verifier/profile' \
--header 'Content-Type: application/json' \
--data-raw '{
    "id" : "<profileID>",
    "name" : "Test Verifier",
    "credentialChecks": [
        "proof"    ],
    "presentationChecks": [
        "proof"
    ]

}'
```

Note: replace `profileID` in the request data  with actual profileID

#### Response
```
{
    "id": "<profileID>",
    "name": "Test Verifier",
    "credentialChecks": [
        "proof"
    ],
    "presentationChecks": [
        "proof"
    ]
}
```

### Get Profile data
#### Request
```
curl --location --request GET 'https://verifier-vcs.sandbox.trustbloc.dev/verifier/profile/<profileID>'
```

Note: replace `<profileID>` in the path param with actual profileID 

#### Response
```
{
    "id": "<profileID>",
    "name": "Test Verifier",
    "credentialChecks": [
        "proof"
    ],
    "presentationChecks": [
        "proof"
    ]
}
```

### Verify Credential
#### Request
```
curl --location --request POST 'https://verifier-vcs.sandbox.trustbloc.dev/<profileID>/verifier/credentials/verify' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer vcs_verifier_rw_token' \
--data-raw '{
   "verifiableCredential": {
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
}'
```

Note: replace `<profileID>` in the path param with actual profileID

#### Response
```
{"checks":["proof"]}
```

### Verify Presentation
#### Request
```
curl --location --request POST 'https://verifier-vcs.sandbox.trustbloc.dev/<profileID>/verifier/presentations/verify' \
--header 'Authorization: Bearer vcs_verifier_rw_token' \
--header 'Content-Type: application/json' \
--data-raw '{
    "verifiablePresentation": {
   "@context":[
      "https://www.w3.org/2018/credentials/v1"
   ],
   "holder":"did:orb:interim:EiAI7Z42NlRQGJgiE9uwHWzYXmMj6Hy3ZKG4W03HbE2WSg",
   "proof":{
      "challenge":"5f59658c-92af-47d2-ae34-7a6bad25a971",
      "created":"2021-08-10T16:51:04.434-04:00",
      "domain":"demo-rp.sandbox.trustbloc.dev",
      "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..XXonuIxi0uEY43FAh7uokTQZk9ZBhhqGLDqsCR6ousiGfXuO6dQxfmvq64Rkko81p_DE-KNp31GuLf4EzYDJBg",
      "proofPurpose":"authentication",
      "type":"Ed25519Signature2018",
      "verificationMethod":"did:orb:interim:EiAI7Z42NlRQGJgiE9uwHWzYXmMj6Hy3ZKG4W03HbE2WSg#dLaiLsP2PQUDZmySYMEHez_YOb6nclnSL391m7Qspb4"
   },
   "type":"VerifiablePresentation",
   "verifiableCredential":[
      {
         "@context":[
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/citizenship/v1",
            "https://w3id.org/vc-revocation-list-2020/v1"
         ],
         "credentialStatus":{
            "id":"https://issuer-vcs.dev.trustbloc.dev/trustbloc-ed25519signature2018-ed25519/status/1#2",
            "revocationListCredential":"https://issuer-vcs.dev.trustbloc.dev/trustbloc-ed25519signature2018-ed25519/status/1",
            "revocationListIndex":"2",
            "type":"RevocationList2020Status"
         },
         "credentialSubject":{
            "birthCountry":"Bahamas",
            "birthDate":"1958-07-17",
            "familyName":"Pasteur",
            "gender":"Male",
            "givenName":"Louis",
            "id":"did:orb:interim:EiAI7Z42NlRQGJgiE9uwHWzYXmMj6Hy3ZKG4W03HbE2WSg",
            "lprCategory":"C09",
            "lprNumber":"999-999-999",
            "residentSince":"2015-01-01",
            "type":[
               "Person",
               "PermanentResident"
            ]
         },
         "description":"Permanent Resident Card of Mr.Louis Pasteur",
         "id":"http://example.com/655fc88e-5b36-456c-8966-e078a0e80b9e",
         "issuanceDate":"2021-08-10T20:49:48.157480804Z",
         "issuer":{
            "id":"did:orb:uAAA:EiCufyNHeMyflfqfZIFlyoDMUEwSMicgCXC2SgAy-8pfiw",
            "name":"trustbloc-ed25519signature2018-ed25519"
         },
         "name":"Permanent Resident Card",
         "proof":{
            "created":"2021-08-10T20:50:28.94658493Z",
            "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..m7KeZ_TKQio0awDv4EH7wg7pKe3pfEHWF8f5M4Fv8jyfPZtBp55C82t6Z2RZFO46-W-yIYs-bEBP96olIHPvDQ",
            "proofPurpose":"assertionMethod",
            "type":"Ed25519Signature2018",
            "verificationMethod":"did:orb:uAAA:EiCufyNHeMyflfqfZIFlyoDMUEwSMicgCXC2SgAy-8pfiw#Obr8RNluDcvC4xRyjP-c3VKX91dymI9Uc87-vvxvPcA"
         },
         "type":[
            "VerifiableCredential",
            "PermanentResidentCard"
         ]
      }
   ]
}
}'
```

Note: replace `<profileID>` in the path param with actual profileID

#### Response
```
{"checks":["proof"]}
```