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

	docdid "github.com/trustbloc/did-go/doc/did"
	ldcontext "github.com/trustbloc/did-go/doc/ld/context"
	lddocloader "github.com/trustbloc/did-go/doc/ld/documentloader"
	ldprocessor "github.com/trustbloc/did-go/doc/ld/processor"
	ldstore "github.com/trustbloc/did-go/doc/ld/store"
	"github.com/trustbloc/did-go/legacy/mem"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vc-go/vermethod"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	respContentType := resp.Header.Get("Content-Type")

	if !strings.HasPrefix(respContentType, "application/json") && respContentType != "" {
		return nil, fmt.Errorf("expected content type is application/json, but got :%s", respContentType)
	}

	return resp, nil
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

type signer struct {
	privateKey []byte
}

func (s *signer) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}

func (s *signer) Alg() string {
	return ""
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
		logger.Error("Failed to close response body", log.WithError(err))
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
		verifiable.WithProofChecker(defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(vdr))),
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
	err = vp.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(loader))
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
	//go:embed contexts/citizenship-v1.jsonld
	citizenshipVocab []byte
	//go:embed contexts/examples-v1.jsonld
	examplesVocabV1 []byte
	//go:embed contexts/examples-v2.jsonld
	examplesVocabV2 []byte
	//go:embed contexts/examples-ext-v1.jsonld
	examplesExtVocab []byte
	//go:embed contexts/examples-crude-product-v1.jsonld
	examplesCrudeProductVocab []byte
	//go:embed contexts/odrl.jsonld
	odrl []byte
	//go:embed contexts/revocation-list-2021.jsonld
	revocationList2021 []byte
	//go:embed contexts/vc-data-integrity-v1.jsonld
	vcDataIntegrity []byte
)

var extraContexts = []ldcontext.Document{ //nolint:gochecknoglobals
	{
		URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		Content: jws2020V1Vocab,
	},
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld", // resolvable
		Content:     citizenshipVocab,
	},
	{
		URL:     "https://www.w3.org/2018/credentials/examples/v1",
		Content: examplesVocabV1,
	},
	{
		URL:     "https://www.w3.org/ns/credentials/examples/v2",
		Content: examplesVocabV2,
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
	{
		URL:         "https://w3c-ccg.github.io/vc-revocation-list-2021/contexts/v1.jsonld",
		DocumentURL: "https://raw.githubusercontent.com/w3c-ccg/vc-status-list-2021/343b8b59cddba4525e1ef355356ae760fc75904e/contexts/v1.jsonld",
		Content:     revocationList2021,
	},
	ldcontext.Document{
		URL:     "https://w3id.org/security/data-integrity/v1",
		Content: vcDataIntegrity,
	},
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

// DocumentLoader returns a JSON-LD document loader with preloaded test contexts.
func DocumentLoader() (*lddocloader.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	loader, err := lddocloader.NewDocumentLoader(ldStore, lddocloader.WithExtraContexts(extraContexts...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}

func IssueAccessToken(ctx context.Context, oidcProviderURL, clientID, secret string, scopes []string) (string, error) {
	conf := clientcredentials.Config{
		TokenURL:     oidcProviderURL + "/oauth2/token",
		ClientID:     clientID,
		ClientSecret: secret,
		Scopes:       scopes,
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	})

	token, err := conf.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	return token.Extra("id_token").(string), nil
}
