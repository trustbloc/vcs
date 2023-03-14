/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/greenpau/go-calculator"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
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

func (s *Steps) getNetworkLatency() error {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: s.tlsConfig,
		},
	}
	apiURL := os.Getenv("VCS_API_URL")

	for i := 0; i < 5; i++ {
		st := time.Now()
		_, err := httpClient.Get(apiURL)
		if err != nil {
			return err
		}
		s.networkLatency = append(s.networkLatency, time.Since(st))
	}

	return nil
}

func (s *Steps) runStressTest(ctx context.Context) error {
	vcsAPIURL := os.Getenv("VCS_API_URL")
	if vcsAPIURL == "" {
		return fmt.Errorf("VCS_API_URL is empty")
	}

	c := clientcredentials.Config{
		TokenURL:     vcsAPIURL + "/cognito/oauth2/token",
		ClientID:     os.Getenv("TOKEN_CLIENT_ID"),
		ClientSecret: os.Getenv("TOKEN_CLIENT_SECRET"),
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: s.tlsConfig,
		},
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	token, tokenErr := c.Token(ctx)
	if tokenErr != nil {
		return fmt.Errorf("failed to get token: %w", tokenErr)
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf("missing id_token")
	}

	workerPool := bddutil.NewWorkerPool(s.concurrentReq, logger)

	workerPool.Start()

	for i := 0; i < s.usersNum; i++ {
		testCase, err := NewTestCase(
			WithVCProviderOption(func(c *vcprovider.Config) {
				c.DidKeyType = "ED25519"
				c.DidMethod = "ion"
				c.InsecureTls = true
				c.KeepWalletOpen = true
			}),
			WithVCSAPIURL(vcsAPIURL),
			WithIssuerProfileID(os.Getenv("ISSUER_PROFILE_ID")),
			WithVerifierProfileID(os.Getenv("VERIFIER_PROFILE_ID")),
			WithCredentialTemplateID(os.Getenv("CREDENTIAL_TEMPLATE_ID")),
			WithHTTPClient(httpClient),
			WithCredentialType("midyVerifiedDocument"),
			WithToken(idToken),
		)
		if err != nil {
			return fmt.Errorf("create test case: %w", err)
		}

		workerPool.Submit(testCase)
	}

	workerPool.Stop()

	perfData := map[string][]time.Duration{}

	for _, resp := range workerPool.Responses() {
		if resp.Err != nil {
			return resp.Err
		}

		perfInfo, ok := resp.Resp.(stressTestPerfInfo)
		if !ok {
			return fmt.Errorf("invalid stressTestPerfInfo response")
		}

		for k, v := range perfInfo {
			perfData[k] = append(perfData[k], v)
		}
	}

	if len(s.networkLatency) > 0 {
		perfData["__network_latency"] = s.networkLatency
	}

	for k, v := range perfData {
		data := make([]int64, len(v))

		for i, d := range v {
			data[i] = d.Milliseconds()
		}

		calc := calculator.NewInt64(data)

		s.stressTestResults[k] = [3]time.Duration{
			time.Duration(calc.Mean().Register.Mean) * time.Millisecond,
			time.Duration(calc.Max().Register.MaxValue) * time.Millisecond,
			time.Duration(calc.Min().Register.MinValue) * time.Millisecond,
		}
	}

	return nil
}

func (s *Steps) displayMetrics() error {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Metric", "AVG", "MAX", "MIN"})

	var metrics []metric
	for k, v := range s.stressTestResults {
		metrics = append(metrics, metric{
			Name: k,
			Avg:  v[0],
			Max:  v[1],
			Min:  v[2],
		})
	}

	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Name < metrics[j].Name
	})

	for _, k := range metrics {
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
