/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddutil

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	_ "embed" //nolint:gci // required for go:embed
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	jsonldcontext "github.com/hyperledger/aries-framework-go/pkg/client/jsonld/context"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("bddutil")

// ProofDataOpts for storing proof options.
type ProofDataOpts struct {
	Challenge string
	Domain    string
}

// ResolveDID waits for the DID to become available for resolution.
func ResolveDID(vdrRegistry vdrapi.Registry, did string, maxRetry int) (*docdid.Doc, error) {
	var docResolution *docdid.DocResolution

	for i := 1; i <= maxRetry; i++ {
		var err error
		docResolution, err = vdrRegistry.Resolve(did)

		if err != nil {
			if !strings.Contains(err.Error(), "DID does not exist") {
				return nil, err
			}

			fmt.Printf("did %s not found will retry %d of %d\n", did, i, maxRetry)
			time.Sleep(3 * time.Second) //nolint:gomnd

			continue
		}

		// check v1 DID is register
		// v1 will return DID with placeholder keys ID (DID#DID) when not register
		// will not return 404
		if strings.Contains(docResolution.DIDDocument.ID, "did:v1") {
			split := strings.Split(docResolution.DIDDocument.AssertionMethod[0].VerificationMethod.ID, "#")
			if strings.Contains(docResolution.DIDDocument.ID, split[1]) {
				fmt.Printf("v1 did %s not register yet will retry %d of %d\n", did, i, maxRetry)
				time.Sleep(3 * time.Second) //nolint:gomnd

				continue
			}
		}
	}

	return docResolution.DIDDocument, nil
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

// HTTPSDo send https request
func HTTPSDo(method, url, contentType, token string, body io.Reader, tlsConfig *tls.Config) (*http.Response, error) {
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

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	return c.Do(req)
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
		return false, fmt.Errorf("error mashalling bytes 1 : %w", err)
	}

	err = json.Unmarshal(b2, &o2)
	if err != nil {
		return false, fmt.Errorf("error mashalling bytes 2 : %w", err)
	}

	return reflect.DeepEqual(o1, o2), nil
}

// CloseResponseBody closes the response body.
func CloseResponseBody(respBody io.Closer) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf("Failed to close response body: %s", err.Error())
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
func CreateCustomPresentation(vcBytes []byte, vdr vdrapi.Registry,
	ldpContext *verifiable.LinkedDataProofContext) ([]byte, error) {
	loader, err := DocumentLoader()
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	// parse vc
	vc, err := verifiable.ParseCredential(vcBytes,
		verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher()),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return nil, err
	}

	// create verifiable presentation from vc
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
	if err != nil {
		return nil, err
	}

	// add linked data proof
	err = vp.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(loader))
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

// nolint:gochecknoglobals //embedded test contexts
var (
	//go:embed contexts/lds-jws2020-v1.jsonld
	jws2020V1Vocab []byte
	//go:embed contexts/governance.jsonld
	governanceVocab []byte
	//go:embed contexts/citizenship-v1.jsonld
	citizenshipVocab []byte
	//go:embed contexts/examples-v1.jsonld
	examplesVocab []byte
	//go:embed contexts/examples-ext-v1.jsonld
	examplesExtVocab []byte
	//go:embed contexts/examples-crude-product-v1.jsonld
	examplesCrudeProductVocab []byte
	//go:embed contexts/odrl.jsonld
	odrl []byte
)

var extraContexts = []jld.ContextDocument{ //nolint:gochecknoglobals
	{
		URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		Content: jws2020V1Vocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/governance/context.jsonld",
		Content: governanceVocab,
	},
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
		Content:     citizenshipVocab,
	},
	{
		URL:     "https://www.w3.org/2018/credentials/examples/v1",
		Content: examplesVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld",
		Content: examplesExtVocab,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-crude-product-v1.jsonld",
		Content: examplesCrudeProductVocab,
	},
	{
		URL:     "https://www.w3.org/ns/odrl.jsonld",
		Content: odrl,
	},
}

// DocumentLoader returns a JSON-LD document loader with preloaded test contexts.
func DocumentLoader() (*jld.DocumentLoader, error) {
	loader, err := jld.NewDocumentLoader(mem.NewProvider(), jld.WithExtraContexts(extraContexts...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}

type httpClient struct {
}

func (c *httpClient) Do(req *http.Request) (*http.Response, error) {
	return HTTPDo(req.Method, req.URL.String(), "", "rw_token", req.Body)
}

// AddJSONLDContexts imports extra contexts for the service instance.
func AddJSONLDContexts(serviceURL string) error {
	const timeout = 5 * time.Second

	client := jsonldcontext.NewClient(serviceURL, jsonldcontext.WithHTTPClient(&httpClient{}))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return client.Add(ctx, extraContexts...)
}
