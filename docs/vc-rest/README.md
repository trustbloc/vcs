## REST API ENDPOINTS 

### 1. Create issuer profile  - POST /profile
This is the first endpoint to continue the flow the in the edge-service. 
Mandatory fields: 
 - name : profile name (example TD etc)
 - [DID](https://www.w3.org/TR/did-core/#dfn-decentralized-identifiers)
 - [uri](https://www.w3.org/TR/vc-data-model/#dfn-uri) 
 - signatureType
 - creator

#### Request 
```
{
		"name": "issuer",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}
```

#### Response
```
{
		"name": "issuer",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
		"created": "010-01-01T19:23:24Z"
}
```
### 2.  Get issuer profile  - GET /profile?id=issuer
This is the first endpoint to continue the flow the in the edge-service. 
Mandatory fields: name, did, uri, signatureType, creator

#### Response
```
{
		"name": "issuer",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}
```
### 3. Create verifiable credential - POST /credential
Mandatory fields: 
- [Types](https://www.w3.org/TR/vc-data-model/#types)
- [CredentialSubject](https://www.w3.org/TR/vc-data-model/#credential-subject)
- profile : name of the profile as created in section 1. 

#### Request 
```
{
    "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
     ],
     "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "university": "MIT"
      },
     "name": "Jayden Doe",
     "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
     },
     "profile": "issuer"
}
```

#### Response
```
{
    "context":"https://www.w3.org/2018/credentials/examples/v1",
    "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
     ],
     "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "university": "MIT"
     },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
    },
    "id": "https://example.com/credentials/c276e12ec21ebfeb1f712ebc6f1",
    "profile": "issuer"
}
```
### 4. Verify verifiable credential - POST /verify

Invokes [aries-framework-go](https://github.com/hyperledger/aries-framework-go/tree/master/pkg/doc/verifiable) to verify the credential

#### Request 
```
{
    "context":"https://www.w3.org/2018/credentials/examples/v1",
    "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
     ],
     "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "university": "MIT"
     },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
    },
    "id": "https://example.com/credentials/c276e12ec21ebfeb1f712ebc6f1",
    "profile": "issuer"
}
```

#### Response
```
{
    "verfied":"true",
    "message": "success"
}
```
### 5. Store verifiable credential - POST /store

You must create the credential before storing the credential in [EDV](https://github.com/trustbloc/edv)

#### Request 
```
{
"profile": "issuer",
"credential" : {
    "context":"https://www.w3.org/2018/credentials/examples/v1",
    "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
     ],
     "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "university": "MIT"
     },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
    },
    "id": "https://example.com/credentials/c276e12ec21ebfeb1f712ebc6f1",
 }
}
```

#### Response
```
Status 200 OK
```

### 6. Retrieve verifiable credential - GET  /retrieve?id=https://example.com/credentials/c276e12ec21ebfeb1f712ebc6f1&profile=issuer
- VC ID as created in section 3 
- Profile name as created in section 1

#### Response
```
{
    "context":"https://www.w3.org/2018/credentials/examples/v1",
    "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
     ],
     "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "university": "MIT"
     },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
    },
    "id": "https://example.com/credentials/c276e12ec21ebfeb1f712ebc6f1",
}
```
