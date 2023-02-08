/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/greenpau/go-calculator"

	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

func (s *Steps) getUsersNum(envVar string) error {
	val := os.Getenv(envVar)
	if val == "" {
		return fmt.Errorf("%s is empty", envVar)
	}

	n, err := strconv.Atoi(val)
	if err != nil {
		return fmt.Errorf("parse %s: %w", envVar, err)
	}

	s.usersNum = n

	return nil
}

func (s *Steps) getDemoIssuerURL(envVar string) error {
	val := os.Getenv(envVar)
	if val == "" {
		return fmt.Errorf("%s is empty", envVar)
	}

	s.demoIssuerURL = val

	return nil
}

func (s *Steps) getDemoVerifierGetQRCodeURL(envVar string) error {
	val := os.Getenv(envVar)
	if val == "" {
		return fmt.Errorf("%s is empty", envVar)
	}

	s.demoVerifierGetQRCodeURL = val

	return nil
}

func (s *Steps) runStressTest() error {
	workerPool := bddutil.NewWorkerPool(1, logger)

	workerPool.Start()

	for i := 0; i < s.usersNum; i++ {
		testCase, cleanup, err := NewTestCase(&TestCaseConfig{
			DemoIssuerURL:            s.demoIssuerURL,
			DemoVerifierGetQRCodeURL: s.demoVerifierGetQRCodeURL,
			DIDKeyType:               "ED25519",
			DIDMethod:                "ion",
			CredentialType:           "midyVerifiedDocument",
			CredentialFormat:         "jwt_vc",
		})
		if err != nil {
			cleanup()
			return fmt.Errorf("create test case: %w", err)
		}

		//defer cleanup()
		workerPool.Submit(testCase)
	}

	workerPool.Stop()

	var (
		preAuthFlowTime []int64
		vpFlowTime      []int64
	)

	for _, resp := range workerPool.Responses() {
		if resp.Err != nil {
			return resp.Err
		}

		perfInfo, ok := resp.Resp.(stressTestPerfInfo)
		if !ok {
			return fmt.Errorf("invalid stressTestPerfInfo response")
		}

		preAuthFlowTime = append(preAuthFlowTime, perfInfo.PreAuthFlowTime)
		vpFlowTime = append(vpFlowTime, perfInfo.VPFlowTime)
	}

	calc := calculator.NewInt64(preAuthFlowTime)

	s.stressTestResults["pre-auth flow"] = [3]time.Duration{
		time.Duration(calc.Mean().Register.Mean) * time.Millisecond,
		time.Duration(calc.Min().Register.MinValue) * time.Millisecond,
		time.Duration(calc.Max().Register.MaxValue) * time.Millisecond,
	}

	calc = calculator.NewInt64(vpFlowTime)

	s.stressTestResults["vp flow"] = [3]time.Duration{
		time.Duration(calc.Mean().Register.Mean) * time.Millisecond,
		time.Duration(calc.Min().Register.MinValue) * time.Millisecond,
		time.Duration(calc.Max().Register.MaxValue) * time.Millisecond,
	}

	return nil
}

func (s *Steps) displayMetrics() error {
	records := [][]string{
		{"metric", "avg", "min", "max"},
	}

	for k, v := range s.stressTestResults {
		records = append(records, []string{
			k,
			v[0].String(),
			v[1].String(),
			v[2].String(),
		})
	}

	w := csv.NewWriter(os.Stdout)

	if err := w.WriteAll(records); err != nil {
		return fmt.Errorf("display metrics: %w", err)
	}

	return nil
}
