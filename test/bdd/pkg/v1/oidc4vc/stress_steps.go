/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"context"
	"encoding/json"
	"errors"
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
	targetClaimData := map[string]interface{}{}
	if err := json.Unmarshal([]byte(os.Getenv("CLAIM_DATA")), &targetClaimData); err != nil {
		return fmt.Errorf("can not unmarshal CLAIM_DATA. %w", err)
	}
	if len(targetClaimData) == 0 {
		return errors.New("CLAIM_DATA should not be empty")
	}
	run := stress.NewStressRun(&stress.Config{
		TLSConfig:              s.tlsConfig,
		ApiURL:                 os.Getenv("VCS_API_URL"),
		TokenClientID:          os.Getenv("TOKEN_CLIENT_ID"),
		TokenClientSecret:      os.Getenv("TOKEN_CLIENT_SECRET"),
		UserCount:              s.usersNum,
		ConcurrentRequests:     s.concurrentReq,
		IssuerProfileID:        os.Getenv("ISSUER_PROFILE_ID"),
		IssuerProfileVersion:   os.Getenv("ISSUER_PROFILE_VERSION"),
		VerifierProfileID:      os.Getenv("VERIFIER_PROFILE_ID"),
		VerifierProfileVersion: os.Getenv("VERIFIER_PROFILE_VERSION"),
		VerifierPresentationID: os.Getenv("VERIFIER_PRESENTATION_ID"),
		CredentialTemplateID:   os.Getenv("CREDENTIAL_TEMPLATE_ID"),
		CredentialType:         os.Getenv("CREDENTIAL_TYPE"),
		ClaimData:              targetClaimData,
	})

	result, err := run.Run(ctx)
	if err != nil {
		return err
	}

	if len(result.Errors) > 0 {
		return result.Errors[0]
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
