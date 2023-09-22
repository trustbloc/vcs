/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/greenpau/go-calculator"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

var logger = log.New("vc-steps")

func (e *Steps) authorizeOrganizationForStressTest(accessTokenURLEnv, orgIDEnv, clientIDEnv, secretEnv string) error {
	accessTokenURL, err := getEnv(accessTokenURLEnv, OidcProviderURL)
	if err != nil {
		return err
	}

	org, err := getEnv(orgIDEnv, "test_org")
	if err != nil {
		return err
	}

	clientID, err := getEnv(clientIDEnv, "profile-user-1")
	if err != nil {
		return err
	}

	secret, err := getEnv(secretEnv, "profile-user-1-pwd")
	if err != nil {
		return err
	}

	accessToken, err := bddutil.IssueAccessToken(context.Background(), accessTokenURL, clientID, secret, []string{"org_admin"})
	if err != nil {
		return err
	}

	e.bddContext.Args[getOrgAuthTokenKey(org)] = accessToken

	return nil
}

//nolint:funlen,gocyclo
func (e *Steps) stressTestForMultipleUsers(
	userEnv,
	vcURLEnv,
	issuerProfileIDEnv,
	verifyProfileIDEnv,
	concurrencyEnv string,
) error {
	concurrencyStr, err := getEnv(concurrencyEnv, "10")
	if err != nil {
		return err
	}

	concurrencyReq, err := strconv.Atoi(concurrencyStr)
	if err != nil {
		return err
	}

	userStr, err := getEnv(userEnv, "10")
	if err != nil {
		return err
	}

	totalRequests, err := strconv.Atoi(userStr)
	if err != nil {
		return err
	}

	vcURL, err := getEnv(vcURLEnv, credentialServiceURL)
	if err != nil {
		return err
	}

	versionedIssuerProfileID, err := getEnv(issuerProfileIDEnv, "i_myprofile_ud_P256k1/v1.0")
	if err != nil {
		return err
	}

	chunks := strings.Split(versionedIssuerProfileID, "/")
	if len(chunks) != 2 {
		return errors.New("invalid issuerProfileID format")
	}

	verifyProfileID, err := getEnv(verifyProfileIDEnv, "v_myprofile_ldp")
	if err != nil {
		return err
	}

	logger.Info("Multi users test", logfields.WithTotalRequests(totalRequests),
		logfields.WithConcurrencyRequests(concurrencyReq))

	createPool := bddutil.NewWorkerPool(concurrencyReq, logger)

	createPool.Start()

	for i := 0; i < totalRequests; i++ {
		r := &stressRequest{
			issuerUrl:            vcURL,
			verifyUrl:            vcURL,
			issuerProfileName:    chunks[0],
			issuerProfileVersion: chunks[1],
			verifyProfileName:    verifyProfileID,
			credential:           "university_degree.json",
			steps:                e,
		}

		createPool.Submit(r)
	}

	createPool.Stop()

	logger.Info("Got vc requests and created responses", logfields.WithResponses(len(createPool.Responses())),
		logfields.WithTotalRequests(totalRequests))

	if len(createPool.Responses()) != totalRequests {
		return fmt.Errorf("expecting created key store %d responses but got %d", totalRequests, len(createPool.Responses()))
	}

	var (
		createVCHTTPTime []int64
		verifyVCHTTPTime []int64
	)

	for _, resp := range createPool.Responses() {
		if resp.Err != nil {
			return resp.Err
		}

		perfInfo, ok := resp.Resp.(stressRequestPerfInfo)
		if !ok {
			return fmt.Errorf("invalid stressRequestPerfInfo response")
		}

		createVCHTTPTime = append(createVCHTTPTime, perfInfo.createVCHTTPTime)
		verifyVCHTTPTime = append(verifyVCHTTPTime, perfInfo.verifyVCHTTPTime)
	}

	calc := calculator.NewInt64(createVCHTTPTime)
	fmt.Printf("results for %d vc requests with concurrent %d\n", totalRequests, concurrencyReq)
	fmt.Printf("create vc avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("create vc max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("create vc min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	calc = calculator.NewInt64(verifyVCHTTPTime)
	fmt.Printf("verify vc avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("verify vc max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("verify vc min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	return nil
}

type stressRequest struct {
	issuerUrl            string
	verifyUrl            string
	credential           string
	issuerProfileName    string
	issuerProfileVersion string
	verifyProfileName    string
	steps                *Steps
}

type stressRequestPerfInfo struct {
	createVCHTTPTime int64
	verifyVCHTTPTime int64
}

func (r *stressRequest) Invoke() (string, interface{}, error) {
	perfInfo := stressRequestPerfInfo{}

	startTime := time.Now()

	credentialID, err := r.steps.createCredential(r.issuerUrl, r.credential,
		r.issuerProfileName, r.issuerProfileVersion, 0)
	if err != nil {
		return credentialID, nil, fmt.Errorf("create vc %w", err)
	}

	perfInfo.createVCHTTPTime = time.Since(startTime).Milliseconds()

	startTime = time.Now()

	res, err := r.steps.getVerificationResult(
		r.verifyUrl, r.verifyProfileName, r.issuerProfileVersion)
	if err != nil {
		return credentialID, nil, err
	}

	if res.Checks != nil {
		return credentialID, nil, fmt.Errorf("credential verification failed")
	}

	perfInfo.verifyVCHTTPTime = time.Since(startTime).Milliseconds()

	return credentialID, perfInfo, nil
}

func getEnv(env, defaultValue string) (string, error) {
	str := os.Getenv(env)
	if str == "" {
		if defaultValue == "" {
			return "", fmt.Errorf("env %s is requried", env)
		}

		return defaultValue, nil
	}

	return str, nil
}
