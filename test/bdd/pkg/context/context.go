/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"fmt"

	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	vdripkg "github.com/hyperledger/aries-framework-go/pkg/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
)

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	Args                            map[string]string
	ProfileRequestTemplate          []byte
	CreateCredentialRequestTemplate []byte
	CreatedCredential               []byte
	CreatedPresentation             []byte
	StoreVCRequest                  []byte
	VDRI                            vdriapi.Registry
}

// NewBDDContext create new BDDContext
func NewBDDContext() (*BDDContext, error) {
	vdri, err := createVDRI("http://localhost:48326/document", "http://localhost:8080/1.0/identifiers")
	if err != nil {
		return nil, err
	}

	instance := BDDContext{
		Args: make(map[string]string),
		ProfileRequestTemplate: []byte(`{
		"name": "ToBeChangedInStep",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018"}`),
		CreateCredentialRequestTemplate: []byte(`{
			"@context": ["https://www.w3.org/2018/credentials/v1"],
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
		VDRI: vdri}

	return &instance, nil
}

func createVDRI(sideTreeURL, universalResolver string) (vdriapi.Registry, error) {
	sideTreeVDRI, err := httpbinding.New(sideTreeURL,
		httpbinding.WithAccept(func(method string) bool { return method == "sidetree" }))
	if err != nil {
		return nil, fmt.Errorf("failed to create new sidetree vdri: %w", err)
	}

	universalResolverVDRI, err := httpbinding.New(universalResolver,
		httpbinding.WithAccept(func(method string) bool { return method == "v1" }))
	if err != nil {
		return nil, fmt.Errorf("failed to create new universal resolver vdri: %w", err)
	}

	vdriProvider, err := context.New(context.WithLegacyKMS(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to create new vdri provider: %w", err)
	}

	return vdripkg.New(vdriProvider, vdripkg.WithVDRI(sideTreeVDRI), vdripkg.WithVDRI(universalResolverVDRI)), nil
}
