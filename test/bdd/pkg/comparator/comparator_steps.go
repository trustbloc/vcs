/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comparator

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
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
)

// Steps is steps for BDD tests
type Steps struct {
	bddContext *context.BDDContext
	client     *client.Comparator
	cshDID     string
	edvToken   string
	kmsToken   string
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

	return &Steps{bddContext: ctx, client: client.New(transport, strfmt.Default)}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Check comparator config is created`, e.checkConfig)
	s.Step(`^Compare two docs with doc1 id "([^"]*)" and doc2 id "([^"]*)"$`, e.compare)
	s.Step(`^Create a new authorization with duration "([^"]*)"$`, e.createAuthorization)
}

func (e *Steps) compare(doc1, doc2 string) error {
	eq := &models.EqOp{}
	query := make([]models.Query, 0)

	vaultID := e.bddContext.VaultID

	query = append(query, &models.DocQuery{DocID: &doc1, VaultID: &vaultID,
		AuthTokens: &models.DocQueryAO1AuthTokens{Kms: e.kmsToken, Edv: e.edvToken}},
		&models.DocQuery{DocID: &doc2, VaultID: &vaultID,
			AuthTokens: &models.DocQueryAO1AuthTokens{Kms: e.kmsToken, Edv: e.edvToken}})

	eq.SetArgs(query)

	cr := models.Comparison{}
	cr.SetOp(eq)

	r, err := e.client.Operations.PostCompare(operations.NewPostCompareParams().
		WithTimeout(requestTimeout).WithComparison(&cr))
	if err != nil {
		return err
	}

	if !r.Payload.Result {
		return fmt.Errorf("compare result not true")
	}

	return nil
}

func (e *Steps) createAuthorization(duration string) error {
	sec, err := strconv.Atoi(duration)
	if err != nil {
		return err
	}

	result, err := vaultclient.New(vaultURL, vaultclient.WithHTTPClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: e.bddContext.TLSConfig,
		}})).CreateAuthorization(
		e.bddContext.VaultID,
		e.cshDID,
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

	e.cshDID = strings.Split(cc.Payload.AuthKeyURL, "#")[0]

	return nil
}
