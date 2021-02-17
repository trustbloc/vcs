/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comparator

import (
	"fmt"

	"github.com/cucumber/godog"

	"github.com/trustbloc/edge-service/pkg/client/comparator"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/openapi"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	comparatorURL = "https://localhost:8065"
)

// Steps is steps for BDD tests
type Steps struct {
	bddContext *context.BDDContext
	client     *comparator.Client
}

// NewSteps returns new steps
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx, client: comparator.New(comparatorURL, comparator.WithTLSConfig(ctx.TLSConfig))}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Check comparator config is created`, e.checkConfig)
	s.Step(`^Compare two docs with doc1 id "([^"]*)" and doc2 id "([^"]*)"$`, e.compare)
}

func (e *Steps) compare(doc1, doc2 string) error {
	eq := &openapi.EqOp{}
	query := make([]openapi.Query, 0)

	vaultID := e.bddContext.VaultID

	query = append(query, &openapi.DocQuery{DocID: &doc1, VaultID: &vaultID})

	eq.SetArgs(query)

	cr := openapi.Comparison{}
	cr.SetOp(eq)

	r, err := e.client.Compare(cr)
	if err != nil {
		return err
	}

	if !r {
		return fmt.Errorf("compare result not true")
	}

	return nil
}

func (e *Steps) checkConfig() error {
	cc, err := e.client.GetConfig()
	if err != nil {
		return err
	}

	if *cc.Did == "" {
		return fmt.Errorf("comparator config DID is empty")
	}

	return nil
}
