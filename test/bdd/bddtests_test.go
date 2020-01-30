/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/godog"

	"github.com/trustbloc/edge-service/test/bdd/dockerutil"
	bddctx "github.com/trustbloc/edge-service/test/bdd/pkg/context"
	"github.com/trustbloc/edge-service/test/bdd/pkg/vc"
)

const profileRequest1 = "${PROFILE_REQUEST1}"
const profileRequest2 = "${PROFILE_REQUEST2}"
const profileRequest3 = "${PROFILE_REQUEST3}"
const profileRequest4 = "${PROFILE_REQUEST4}"
const profileRequest5 = "${PROFILE_REQUEST5}"
const expectedProfileResponse1 = "${EXPECTED_PROFILE_RESPONSE1}"
const expectedProfileResponse2 = "${EXPECTED_PROFILE_RESPONSE2}"
const expectedProfileResponse3 = "${EXPECTED_PROFILE_RESPONSE3}"
const expectedProfileResponse4 = "${EXPECTED_PROFILE_RESPONSE4}"
const expectedProfileResponse5 = "${EXPECTED_PROFILE_RESPONSE5}"

const credentialRequest1 = "${CREDENTIAL_REQUEST1}"
const credentialRequest2 = "${CREDENTIAL_REQUEST2}"
const credentialRequest3 = "${CREDENTIAL_REQUEST3}"

const storeVCRequest1 = "${STORE_VC_REQUEST1}"
const storeVCRequest2 = "${STORE_VC_REQUEST2}"

const validVC = "${VALID_VC}"

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all
	tags := "all"

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" {
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	status := runBDDTests(tags, format)
	if st := m.Run(); st > status {
		status = st
	}

	os.Exit(status)
}

func runBDDTests(tags, format string) int {
	return godog.RunWithOptions("godogs", func(s *godog.Suite) {
		var composition []*dockerutil.Composition
		var composeFiles = []string{"./fixtures/vc-rest", "./fixtures/edv-rest"}
		s.BeforeSuite(func() {
			if os.Getenv("DISABLE_COMPOSITION") != "true" {
				// Need a unique name, but docker does not allow '-' in names
				composeProjectName := strings.ReplaceAll(generateUUID(), "-", "")

				for _, v := range composeFiles {
					newComposition, err := dockerutil.NewComposition(composeProjectName, "docker-compose.yml", v)
					if err != nil {
						panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
					}
					composition = append(composition, newComposition)
				}
				fmt.Println("docker-compose up ... waiting for containers to start ...")
				testSleep := 5
				if os.Getenv("TEST_SLEEP") != "" {
					var e error

					testSleep, e = strconv.Atoi(os.Getenv("TEST_SLEEP"))
					if e != nil {
						panic(fmt.Sprintf("Invalid value found in 'TEST_SLEEP': %s", e))
					}
				}
				fmt.Printf("*** testSleep=%d", testSleep)
				println()
				time.Sleep(time.Second * time.Duration(testSleep))
			}
		})
		s.AfterSuite(func() {
			for _, c := range composition {
				if c != nil {
					if err := c.GenerateLogs(c.Dir, c.ProjectName+".log"); err != nil {
						panic(err)
					}
					if _, err := c.Decompose(c.Dir); err != nil {
						panic(err)
					}
				}
			}
		})
		FeatureContext(s)
	}, godog.Options{
		Tags:          tags,
		Format:        format,
		Paths:         []string{"features"},
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	})
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

// generateUUID returns a UUID based on RFC 4122
func generateUUID() string {
	id := dockerutil.GenerateBytesUUID()
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func FeatureContext(s *godog.Suite) {
	bddContext, err := bddctx.NewBDDContext()
	if err != nil {
		panic(fmt.Sprintf("Error returned from NewBDDContext: %s", err))
	}

	// set dynamic args
	bddContext.Args[profileRequest1] = `{
		"name": "profile1",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`

	bddContext.Args[profileRequest2] = `{
		"name": "profile2",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`
	bddContext.Args[profileRequest3] = `{
		"name": "profile3",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`
	bddContext.Args[profileRequest4] = `{
		"name": "profile4",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`
	bddContext.Args[profileRequest5] = `{
		"name": "profile5",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`

	bddContext.Args[expectedProfileResponse1] = `{
		"name": "profile1",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`

	bddContext.Args[expectedProfileResponse2] = `{
		"name": "profile2",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`
	bddContext.Args[expectedProfileResponse3] = `{
		"name": "profile3",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`
	bddContext.Args[expectedProfileResponse4] = `{
		"name": "profile4",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`
	bddContext.Args[expectedProfileResponse5] = `{
		"name": "profile5",
		"did": "did:peer:22",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"creator": "did:peer:22#key1"
}`

	bddContext.Args[credentialRequest1] = `{
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
  "profile": "profile3"
}`

	bddContext.Args[credentialRequest2] = `{
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
  "profile": "profile4"
}`
	bddContext.Args[credentialRequest3] = `{
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
  "profile": "profile5"
}`

	bddContext.Args[storeVCRequest1] = `{
"profile": "profile4",
"credential" : {
	"@context":"https://www.w3.org/2018/credentials/examples/v1",
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
  	"id": "https://example.com/credentials/1872",
  	"issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
    }
  }
}`

	bddContext.Args[storeVCRequest2] = `{
"profile": "profile5",
"credential" : {
	"@context":"https://www.w3.org/2018/credentials/examples/v1",
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
  	"id": "https://example.com/credentials/1872",
  	"issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
    }
  }
}`

	bddContext.Args[validVC] = `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "id": "http://example.edu/credentials/1872",
  "type": "VerifiableCredential",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  },
  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },
  "issuanceDate": "2010-01-01T19:23:24Z"
}`

	vc.NewSteps(bddContext).RegisterSteps(s)
}
