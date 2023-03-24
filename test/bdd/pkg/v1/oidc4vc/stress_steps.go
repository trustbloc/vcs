/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

func (s *Steps) getUsersNum(envVar, concurrentReqEnv string) error {
	val := os.Getenv(envVar)
	if val == "" {
		return fmt.Errorf("%s is empty", envVar)
	}

	n, err := strconv.Atoi(val)
	if err != nil {
		return fmt.Errorf("parse %s: %w", envVar, err)
	}

	s.usersNum = n

	val = os.Getenv(concurrentReqEnv)
	if val == "" {
		return fmt.Errorf("%s is empty", concurrentReqEnv)
	}

	n, err = strconv.Atoi(val)
	if err != nil {
		return fmt.Errorf("parse %s: %w", concurrentReqEnv, err)
	}

	s.concurrentReq = n

	return nil
}

func (s *Steps) runStressTest(ctx context.Context) error {
	run := stress.NewStressRun(&stress.Config{
		TLSConfig:            s.tlsConfig,
		ApiURL:               os.Getenv("VCS_API_URL"),
		TokenClientID:        os.Getenv("TOKEN_CLIENT_ID"),
		TokenClientSecret:    os.Getenv("TOKEN_CLIENT_SECRET"),
		UserCount:            s.usersNum,
		ConcurrentRequests:   s.concurrentReq,
		IssuerProfileID:      os.Getenv("ISSUER_PROFILE_ID"),
		VerifierProfileID:    os.Getenv("VERIFIER_PROFILE_ID"),
		CredentialTemplateID: os.Getenv("CREDENTIAL_TEMPLATE_ID"),
		CredentialType:       "midyVerifiedDocument",
		ClaimData: map[string]interface{}{
			"type":              []string{"midyVerifiedPassport"},
			"birthdate":         "1990-08-02",
			"expiry_date":       "2029-05-06",
			"doc_number":        "34234234123",
			"doc_type":          "passport",
			"given_name":        "Harry",
			"issue_date":        "2019-05-06",
			"nationality":       "CA",
			"issuing_country":   "CA",
			"issuing_authority": "CA",
			"family_name":       "Tester",
		},
	})

	result, err := run.Run(ctx)
	if err != nil {
		return err
	}

	s.stressResult = result

	return nil
}

func (s *Steps) displayMetrics() error {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Metric", "AVG", "MAX", "MIN"})

	for _, k := range s.stressResult.Metrics {
		t.AppendRow(table.Row{
			k.Name,
			k.Avg.String(),
			k.Max.String(),
			k.Min.String(),
		})
	}

	t.Render()

	return nil
}
