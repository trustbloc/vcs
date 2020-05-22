/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariessigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	log "github.com/sirupsen/logrus"
)

// ProofDataOpts for storing proof options.
type ProofDataOpts struct {
	Challenge string
	Domain    string
}

// ResolveDID waits for the DID to become available for resolution.
func ResolveDID(vdriRegistry vdriapi.Registry, did string, maxRetry int) (*docdid.Doc, error) {
	var didDoc *docdid.Doc

	for i := 1; i <= maxRetry; i++ {
		var err error
		didDoc, err = vdriRegistry.Resolve(did)

		if err != nil {
			if !strings.Contains(err.Error(), "DID does not exist") {
				return nil, err
			}

			fmt.Printf("did %s not found will retry %d of %d\n", did, i, maxRetry)
			time.Sleep(3 * time.Second)

			continue
		}

		// check v1 DID is register
		// v1 will return DID with placeholder keys ID (DID#DID) when not register
		// will not return 404
		if strings.Contains(didDoc.ID, "did:v1") {
			split := strings.Split(didDoc.AssertionMethod[0].PublicKey.ID, "#")
			if strings.Contains(didDoc.ID, split[1]) {
				fmt.Printf("v1 did %s not register yet will retry %d of %d\n", did, i, maxRetry)
				time.Sleep(3 * time.Second)

				continue
			}
		}
	}

	return didDoc, nil
}

// HTTPDo send http request
func HTTPDo(method, url, contentType, token string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}

	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	return http.DefaultClient.Do(req)
}

// CreatePresentation creates verifiable presentation from verifiable credential.
func CreatePresentation(vcBytes []byte, signatureType, domain, challenge string,
	representation verifiable.SignatureRepresentation, vdri vdriapi.Registry, doc *docdid.Doc) ([]byte, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var signatureSuite ariessigner.SignatureSuite

	switch signatureType {
	case "Ed25519Signature2018":
		signatureSuite = ed25519signature2018.New(suite.WithSigner(GetSigner(privateKey)))
	case "JsonWebSignature2020":
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(GetSigner(privateKey)))
	}

	// authentication public key

	authVMS := doc.VerificationMethods(docdid.Authentication)[docdid.Authentication]
	if len(authVMS) == 0 {
		return nil, fmt.Errorf("invalid did to create presentation, expected atleast one authentication public key")
	}

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           signatureType,
		SignatureRepresentation: representation,
		Suite:                   signatureSuite,
		Challenge:               challenge,
		Domain:                  domain,
		VerificationMethod:      authVMS[0].PublicKey.ID,
	}

	return CreateCustomPresentation(vcBytes, vdri, ldpContext)
}

// GetSigner returns private key based signer for bdd tests
func GetSigner(privKey []byte) verifiable.Signer {
	return &signer{privateKey: privKey}
}

type signer struct {
	privateKey []byte
}

func (s *signer) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}

// ExpectedStringError formats the response error message.
func ExpectedStringError(expected, actual string) error {
	return fmt.Errorf("expected %s but got %s instead", expected, actual)
}

// ExpectedStatusCodeError formats the status code error message.
func ExpectedStatusCodeError(expected, actual int, respBytes []byte) error {
	return fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
		expected, actual, respBytes)
}

// AreEqualJSON compares if 2 JSON bytes are equal
func AreEqualJSON(b1, b2 []byte) (bool, error) {
	var o1, o2 interface{}

	err := json.Unmarshal(b1, &o1)
	if err != nil {
		return false, fmt.Errorf("error mashalling bytes 1 : %s", err.Error())
	}

	err = json.Unmarshal(b2, &o2)
	if err != nil {
		return false, fmt.Errorf("error mashalling bytes 2 : %s", err.Error())
	}

	return reflect.DeepEqual(o1, o2), nil
}

// CloseResponseBody closes the response body.
func CloseResponseBody(respBody io.Closer) {
	err := respBody.Close()
	if err != nil {
		log.Errorf("Failed to close response body: %s", err.Error())
	}
}

// GetProfileNameKey key for storing profile name.
func GetProfileNameKey(user string) string {
	return user + "-profileName"
}

// GetCredentialKey key for storing credential.
func GetCredentialKey(user string) string {
	return user + "-vc"
}

// GetPresentationKey key for storing presentation.
func GetPresentationKey(user string) string {
	return user + "-vp"
}

// GetOptionsKey key for storing options.
func GetOptionsKey(user string) string {
	return user + "-opts"
}

// GetProofChallengeKey key for storing proof challenge.
func GetProofChallengeKey(user string) string {
	return user + "-challenge"
}

// GetProofDomainKey key for storing proof domain.
func GetProofDomainKey(user string) string {
	return user + "-domain"
}

// GetIssuerHolderCommKey key for storing data moving between issuer and holder.
func GetIssuerHolderCommKey(issuer, holder string) string {
	return issuer + holder + "-data"
}

// GetDIDDocKey key for storing did DOC.
func GetDIDDocKey(user string) string {
	return user + "-did-doc"
}

// CreateCustomPresentation creates verifiable presentation from custom linked data proof context
func CreateCustomPresentation(vcBytes []byte, vdri vdriapi.Registry,
	ldpContext *verifiable.LinkedDataProofContext) ([]byte, error) {
	// parse vc
	vc, err := verifiable.ParseCredential(vcBytes,
		verifiable.WithPublicKeyFetcher(verifiable.NewDIDKeyResolver(vdri).PublicKeyFetcher()))
	if err != nil {
		return nil, err
	}

	// create verifiable presentation from vc
	vp, err := vc.Presentation()
	if err != nil {
		return nil, err
	}

	// add linked data proof
	err = vp.AddLinkedDataProof(ldpContext)
	if err != nil {
		return nil, err
	}

	return json.Marshal(vp)
}

// GetSignatureRepresentation parse signature representation
func GetSignatureRepresentation(holder string) verifiable.SignatureRepresentation {
	switch holder {
	case "JWS":
		return verifiable.SignatureJWS
	case "ProofValue":
		return verifiable.SignatureProofValue
	default:
		return verifiable.SignatureJWS
	}
}
