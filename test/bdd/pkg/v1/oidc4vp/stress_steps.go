/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/greenpau/go-calculator"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

var logger = log.New("oidc4vp-steps")

//nolint:funlen,gocyclo
func (e *Steps) stressTestForMultipleUsers(userEnv, initiateInteractionURLFormatEnv,
	retrieveClaimURLFormatEnv,
	verifyProfileIDEnv, orgIDEnv, concurrencyEnv string) error {
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

	initiateInteractionURLFormat, err := getEnv(initiateInteractionURLFormatEnv, initiateOidcInteractionURLFormat)
	if err != nil {
		return err
	}

	retrieveClaimURLFormat, err := getEnv(retrieveClaimURLFormatEnv, retrieveInteractionsClaimURLFormat)
	if err != nil {
		return err
	}

	verifyProfileID, err := getEnv(verifyProfileIDEnv, "v_myprofile_jwt")
	if err != nil {
		return err
	}

	orgID, err := getEnv(orgIDEnv, "test_org")
	if err != nil {
		return err
	}

	authToken := e.bddContext.Args[getOrgAuthTokenKey(orgID)]

	logger.Info("Multi users test", logfields.WithTotalRequests(totalRequests), logfields.WithConcurrencyRequests(concurrencyReq))

	createPool := bddutil.NewWorkerPool(concurrencyReq, logger)

	createPool.Start()

	for i := 0; i < totalRequests; i++ {
		r := &stressRequest{
			vpFlowExecutor: &VPFlowExecutor{
				tlsConfig:      e.tlsConfig,
				ariesServices:  e.ariesServices,
				wallet:         e.wallet,
				walletToken:    e.walletToken,
				walletDidID:    e.walletDidID,
				walletDidKeyID: e.walletDidKeyID,
				URLs: &VPFlowExecutorURLs{
					InitiateOidcInteractionURLFormat:   initiateInteractionURLFormat,
					RetrieveInteractionsClaimURLFormat: retrieveClaimURLFormat,
				},
			},
			authToken:   authToken,
			profileName: verifyProfileID,
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
		initiateHTTPTime                  []int64
		checkAuthorizedResponseHTTPTime   []int64
		retrieveInteractionsClaimHTTPTime []int64
	)

	for _, resp := range createPool.Responses() {
		if resp.Err != nil {
			return resp.Err
		}

		perfInfo, ok := resp.Resp.(stressRequestPerfInfo)
		if !ok {
			return fmt.Errorf("invalid stressRequestPerfInfo response")
		}

		initiateHTTPTime = append(initiateHTTPTime, perfInfo.initiateHTTPTime)
		checkAuthorizedResponseHTTPTime = append(checkAuthorizedResponseHTTPTime, perfInfo.checkAuthorizedResponseHTTPTime)
		retrieveInteractionsClaimHTTPTime = append(retrieveInteractionsClaimHTTPTime, perfInfo.retrieveInteractionsClaimHTTPTime)
	}

	calc := calculator.NewInt64(initiateHTTPTime)
	fmt.Printf("results for %d vc requests with concurrent %d\n", totalRequests, concurrencyReq)
	fmt.Printf("initiate avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("initiate vc max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("initiate vc min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	calc = calculator.NewInt64(checkAuthorizedResponseHTTPTime)
	fmt.Printf("check authorized response avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("check authorized response max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("check authorized response min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	calc = calculator.NewInt64(retrieveInteractionsClaimHTTPTime)
	fmt.Printf("retrieve claims avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("retrieve claims max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("retrieve claims min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	return nil
}

type stressRequest struct {
	vpFlowExecutor *VPFlowExecutor

	authToken   string
	profileName string
}

type stressRequestPerfInfo struct {
	initiateHTTPTime                  int64
	checkAuthorizedResponseHTTPTime   int64
	retrieveInteractionsClaimHTTPTime int64
}

func (r *stressRequest) Invoke() (interface{}, error) {
	perfInfo := stressRequestPerfInfo{}

	println("initiateInteraction started")

	startTime := time.Now()
	err := r.vpFlowExecutor.initiateInteraction(r.profileName, r.authToken)
	if err != nil {
		return nil, fmt.Errorf("initiate interaction %w", err)
	}

	perfInfo.initiateHTTPTime = time.Since(startTime).Milliseconds()

	println("fetchRequestObject started")

	rawRequestObject, err := r.vpFlowExecutor.fetchRequestObject()
	if err != nil {
		return nil, fmt.Errorf("featch request object %w", err)
	}

	err = r.vpFlowExecutor.verifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
	if err != nil {
		return nil, fmt.Errorf("verify authorization request %w", err)
	}

	err = r.vpFlowExecutor.queryCredentialFromWallet()
	if err != nil {
		return nil, fmt.Errorf("query credential from wallet %w", err)
	}

	authorizedResponse, err := r.vpFlowExecutor.createAuthorizedResponse()
	if err != nil {
		return nil, err
	}

	startTime = time.Now()

	err = r.vpFlowExecutor.sendAuthorizedResponse(authorizedResponse)
	if err != nil {
		return nil, err
	}

	perfInfo.checkAuthorizedResponseHTTPTime = time.Since(startTime).Milliseconds()

	startTime = time.Now()

	err = r.vpFlowExecutor.retrieveInteractionsClaim(r.vpFlowExecutor.transactionID, r.authToken, http.StatusOK)
	if err != nil {
		return nil, err
	}

	perfInfo.retrieveInteractionsClaimHTTPTime = time.Since(startTime).Milliseconds()

	return perfInfo, nil
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
