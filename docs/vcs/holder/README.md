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
            "https://www.w3.org/2018/credentials/v1"
        ],
        "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
        "type": "VerifiablePresentation",
        "verifiableCredential": [
            {
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
                "proof": {
                    "created": "2022-03-04T18:25:06.570834906Z",
                    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MB9eO_6ybmsqZeMjUHNvzPI8zHB3TFcJJPjGXjM4XCXFX3XScM05s37-x9R92wSj7NxKfEEr18aYJXBnL7EpDg",
                    "proofPurpose": "assertionMethod",
                    "type": "Ed25519Signature2018",
                    "verificationMethod": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd"
                },
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ]
            }
        ]
    }
}'
```

Note: replace `<profileID>` in the path param with actual profileID

#### Response
```
{
   "@context":[
      "https://www.w3.org/2018/credentials/v1"
   ],
   "holder":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
   "id":"urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
   "type":"VerifiablePresentation",
   "verifiableCredential":[
      {
         "@context":[
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
            "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
         ],
         "credentialSubject":{
            "degree":{
               "degree":"Bachelor of Science and Arts",
               "type":"BachelorDegree"
            },
            "id":"did:trustbloc:4vSjd:EiAQcxO7cXUge_EV54by9ehz6KsDXmsRG59fLSsZiUPOJw",
            "name":"Jayden Doe"
         },
         "description":"University Degree Credential for Mr.Jayden Doe",
         "id":"http://example.com/678e0dfd-99db-418f-9fc3-6582f8b18bd0",
         "issuanceDate":"2021-08-10T14:06:39.829544433Z",
         "issuer":{
            "id":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
            "name":"vc-issuer-interop-key"
         },
         "name":"University Degree Credential",
         "proof":{
            "created":"2022-03-04T18:25:06.570834906Z",
            "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MB9eO_6ybmsqZeMjUHNvzPI8zHB3TFcJJPjGXjM4XCXFX3XScM05s37-x9R92wSj7NxKfEEr18aYJXBnL7EpDg",
            "proofPurpose":"assertionMethod",
            "type":"Ed25519Signature2018",
            "verificationMethod":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd"
         },
         "type":[
            "VerifiableCredential",
            "UniversityDegreeCredential"
         ]
      }
   ],
   "proof":{
      "created":"2022-03-04T18:34:44.076655752Z",
      "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..hmnFU1F757asx0mU6gMiyOp8Q7UCVzi7Lcb2GMBnc0Br5KA73EwOS6n3GrBVe-UTnVgFGnr9IfPrJIp5Qz98AQ",
      "proofPurpose":"authentication",
      "type":"Ed25519Signature2018",
      "verificationMethod":"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd"
   }
}
```
