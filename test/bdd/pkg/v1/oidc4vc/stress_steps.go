/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/greenpau/go-calculator"

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
	workerPool := bddutil.NewWorkerPool(s.concurrentReq, logger)

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
	records := [][]string{
		{"metric", "avg", "max", "min"},
	}

	sortedByAvg := make([]string, 0, len(s.stressTestResults))

	for k := range s.stressTestResults {
		sortedByAvg = append(sortedByAvg, k)
	}

	sort.Slice(sortedByAvg, func(i, j int) bool {
		return s.stressTestResults[sortedByAvg[i]][0] > s.stressTestResults[sortedByAvg[j]][0]
	})

	for _, k := range sortedByAvg {
		records = append(records, []string{
			k,
			s.stressTestResults[k][0].String(),
			s.stressTestResults[k][1].String(),
			s.stressTestResults[k][2].String(),
		})
	}

	w := csv.NewWriter(os.Stdout)

	if err := w.WriteAll(records); err != nil {
		return fmt.Errorf("display metrics: %w", err)
	}

	return nil
}
