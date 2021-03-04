/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comparator

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/cucumber/godog"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edge-service/pkg/client/comparator/client"
	"github.com/trustbloc/edge-service/pkg/client/comparator/client/operations"
	"github.com/trustbloc/edge-service/pkg/client/comparator/models"
	vaultclient "github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	comparatorURL  = "localhost:8065"
	vaultURL       = "https://localhost:9099"
	requestTimeout = 5 * time.Second
	expiryDuration = int64(300) // nolint: gomnd
)

// Steps is steps for BDD tests
type Steps struct {
	bddContext     *context.BDDContext
	client         *client.Comparator
	cshAuthKey     string
	edvToken       string
	kmsToken       string
	authorizations map[string]*models.Authorization
}

// NewSteps returns new steps
func NewSteps(ctx *context.BDDContext) *Steps {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: ctx.TLSConfig,
		},
	}

	transport := httptransport.NewWithClient(
		comparatorURL,
		client.DefaultBasePath,
		[]string{"https"},
		httpClient,
	)

	return &Steps{
		bddContext:     ctx,
		client:         client.New(transport, strfmt.Default),
		authorizations: make(map[string]*models.Authorization),
	}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Create comparator authorization for doc "([^"]*)"$`, e.createAuthorization)
	s.Step(`^Check comparator config is created`, e.checkConfig)
	s.Step(`^Compare two docs with doc1 id "([^"]*)" and ref for doc2 id "([^"]*)" with compare result "([^"]*)"$`, e.compare)                                                                                  // nolint:lll
	s.Step(`^Extract docs from auth tokens received from comparator authorization for docIDs "([^"]*)", "([^"]*)", "([^"]*)" and validate data equal "([^"]*)", "([^"]*)", "([^"]*)" respectively$`, e.extract) // nolint:lll
	s.Step(`^Create vault authorization with duration "([^"]*)"$`, e.createVaultAuthorization)
}

func (e *Steps) createAuthorization(docID string) error {
	keyManager, err := localkms.New(
		"local-lock://test/key-uri/",
		&mockKMSProvider{
			sp: mem.NewProvider(),
			sl: &noop.NoLock{},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to init local kms: %w", err)
	}

	localcrypto, err := tinkcrypto.New()
	if err != nil {
		return fmt.Errorf("failed to init local crypto: %w", err)
	}

	signer, err := signature.NewCryptoSigner(localcrypto, keyManager, kms.ED25519Type)
	if err != nil {
		return fmt.Errorf("failed to create a new signer: %w", err)
	}

	rpID := didKeyURL(signer.PublicKeyBytes())

	vaultID := e.bddContext.VaultID

	scope := &models.Scope{
		VaultID:     vaultID,
		DocID:       &docID,
		DocAttrPath: "$.contents", // vault server BDD tests are saving contents under this path
		Actions:     []string{"compare"},
		AuthTokens: &models.ScopeAuthTokens{
			Edv: e.edvToken,
			Kms: e.kmsToken,
		},
	}

	caveat := make([]models.Caveat, 0)
	caveat = append(caveat, &models.ExpiryCaveat{Duration: expiryDuration})

	scope.SetCaveats(caveat)

	r, err := e.client.Operations.PostAuthorizations(operations.NewPostAuthorizationsParams().
		WithTimeout(requestTimeout).WithAuthorization(&models.Authorization{
		RequestingParty: &rpID,
		Scope:           scope,
	}))
	if err != nil {
		return err
	}

	e.authorizations[docID] = r.Payload

	return nil
}

func (e *Steps) extract(doc1, doc2, doc3, data1, data2, data3 string) error {
	docs := make(map[string]string)

	doc1Query := &models.AuthorizedQuery{AuthToken: &e.authorizations[doc1].AuthToken}
	doc1Query.SetID(uuid.New().String())

	docs[doc1Query.ID()] = data1

	doc2Query := &models.AuthorizedQuery{AuthToken: &e.authorizations[doc2].AuthToken}
	doc2Query.SetID(uuid.New().String())

	docs[doc2Query.ID()] = data2

	doc3Query := &models.AuthorizedQuery{AuthToken: &e.authorizations[doc3].AuthToken}
	doc3Query.SetID(uuid.New().String())

	docs[doc3Query.ID()] = data3

	request := &models.Extract{}
	request.SetQueries([]models.Query{doc1Query, doc2Query, doc3Query})

	r, err := e.client.Operations.PostExtract(operations.NewPostExtractParams().
		WithTimeout(requestTimeout).WithExtract(request))
	if err != nil {
		return err
	}

	if len(r.Payload.Documents) == 0 {
		return errors.New("confidential storage hub failed to return extractions")
	}

	for queryID, data := range docs {
		var extraction *models.ExtractRespDocumentsItems0

		for j := range r.Payload.Documents {
			if r.Payload.Documents[j].ID == queryID {
				extraction = r.Payload.Documents[j]

				break
			}
		}

		if extraction == nil {
			return fmt.Errorf("no result returned for queryID %s (data %s)", queryID, data)
		}

		respDoc, ok := extraction.Contents.(string)
		if !ok {
			return fmt.Errorf("doc is not string")
		}

		if data != respDoc {
			return fmt.Errorf("doc not equal to %s", data)
		}
	}

	return nil
}

func (e *Steps) compare(doc1, doc2, result string) error {
	eq := &models.EqOp{}
	query := make([]models.Query, 0)

	vaultID := e.bddContext.VaultID

	query = append(
		query,
		&models.DocQuery{
			DocID:       &doc1,
			VaultID:     &vaultID,
			DocAttrPath: "$.contents", // vault server BDD tests are saving contents under this path
			AuthTokens: &models.DocQueryAO1AuthTokens{
				Kms: e.kmsToken,
				Edv: e.edvToken,
			},
		},
		&models.AuthorizedQuery{AuthToken: &e.authorizations[doc2].AuthToken},
	)

	eq.SetArgs(query)

	cr := models.Comparison{}
	cr.SetOp(eq)

	r, err := e.client.Operations.PostCompare(operations.NewPostCompareParams().
		WithTimeout(requestTimeout).WithComparison(&cr))
	if err != nil {
		return err
	}

	res, err := strconv.ParseBool(result)
	if err != nil {
		return err
	}

	if r.Payload.Result != res {
		return fmt.Errorf("compare result not %t", res)
	}

	return nil
}

func (e *Steps) createVaultAuthorization(duration string) error {
	sec, err := strconv.Atoi(duration)
	if err != nil {
		return err
	}

	result, err := vaultclient.New(vaultURL, vaultclient.WithHTTPClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: e.bddContext.TLSConfig,
		},
	})).CreateAuthorization(
		e.bddContext.VaultID,
		e.cshAuthKey,
		&vault.AuthorizationsScope{
			Target:  e.bddContext.VaultID,
			Actions: []string{"read"},
			Caveats: []vault.Caveat{{Type: zcapld.CaveatTypeExpiry, Duration: uint64(sec)}},
		},
	)
	if err != nil {
		return err
	}

	if result.ID == "" {
		return fmt.Errorf("id is empty")
	}

	e.edvToken = result.Tokens.EDV
	e.kmsToken = result.Tokens.KMS

	return nil
}

func (e *Steps) checkConfig() error {
	cc, err := e.client.Operations.GetConfig(operations.NewGetConfigParams().
		WithTimeout(requestTimeout))
	if err != nil {
		return err
	}

	if *cc.Payload.Did == "" {
		return fmt.Errorf("comparator config DID is empty")
	}

	e.cshAuthKey = cc.Payload.AuthKeyURL

	return nil
}

type mockKMSProvider struct {
	sp ariesstorage.Provider
	sl secretlock.Service
}

func (m *mockKMSProvider) StorageProvider() ariesstorage.Provider {
	return m.sp
}

func (m *mockKMSProvider) SecretLock() secretlock.Service {
	return m.sl
}

func didKeyURL(pubKeyBytes []byte) string {
	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}
