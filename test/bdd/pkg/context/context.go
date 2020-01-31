/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	Args                            map[string]string
	ProfileRequestTemplate          []byte
	CreateCredentialRequestTemplate []byte
	CreatedCredential               []byte
	StoreVCRequest                  []byte
}

// NewBDDContext create new BDDContext
func NewBDDContext() (*BDDContext, error) {
	instance := BDDContext{
		Args: make(map[string]string),
		ProfileRequestTemplate: []byte(`{
		"name": "ToBeChangedInStep",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`),
		CreateCredentialRequestTemplate: []byte(`{
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
  "profile": "ToBeChangedInStep"
}`),
		StoreVCRequest: []byte(`{
"profile": "ToBeChangedInStep",
"credential" : "{\"@context\":[\"https:\/\/www.w3.org\/2018\/credentials\/v1\"],\"credentialSchema\":[],` +
			`\"credentialSubject\":{\"degree\":{\"type\":\"BachelorDegree\",\"university\":\"MIT\"},\"id\":` +
			`\"did:example:ebfeb1f712ebc6f1c276e12ec21\",\"name\":\"Jayden Doe\",\"spouse\":\` +
			`"did:example:c276e12ec21ebfeb1f712ebc6f1\"},\"id\":\` +
			`"https:\/\/example.com\/credentials\/60ee5363-be83-4f6b-b4a5-894a678fdcfa\",\"issuanceDate\":` +
			`\"2020-01-31T00:05:14.2705985Z\",\"issuer\":{\"id\":\"did:peer:22\",\"name\":\"MyProfile\"},\"proof\"` +
			`:{\"created\":\"2020-01-31T00:05:14Z\",\"creator\":\"did:peer:22#key1\",\"domain\":\"\",\"nonce` +
			`\":\"\",\"proofValue\":\` +
			`"pm4VBH74TXY_JKYcTX5J-iygJDv-rTvs8J8VTrpdoMjd3DsVNIiHM33b5vMm336wkYqmYhaxWPOsMnrCsQNTBw\",\"type\":\` +
			`"Ed25519Signature2018\"},\"type\":[\"VerifiableCredential\",\"UniversityDegreeCredential\"]}"
}`),
	}

	return &instance, nil
}
