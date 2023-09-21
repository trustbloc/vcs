/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"encoding/json"
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

var logger = log.New("oidc4vp-steps")

//nolint:funlen,gocyclo
func (e *Steps) stressTestForMultipleUsers(
	userEnv,
	initiateInteractionURLFormatEnv,
	retrieveClaimURLFormatEnv,
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

	initiateInteractionURLFormat, err := getEnv(initiateInteractionURLFormatEnv, initiateOidcInteractionURLFormat)
	if err != nil {
		return err
	}

	retrieveClaimURLFormat, err := getEnv(retrieveClaimURLFormatEnv, retrieveInteractionsClaimURLFormat)
	if err != nil {
		return err
	}

	verifyProfile, err := getEnv(verifyProfileIDEnv, "v_myprofile_jwt/v1.0")
	if err != nil {
		return err
	}

	initiateOIDC4VPPayload, err := json.Marshal(&initiateOIDC4VPData{
		PresentationDefinitionId: "32f54163-no-limit-disclosure-single-field",
		PresentationDefinitionFilters: &presentationDefinitionFilters{
			Fields: &([]string{"degree_type_id"}),
		},
	})
	if err != nil {
		return err
	}

	chunks := strings.Split(verifyProfile, "/")
	if len(chunks) != 2 {
		return fmt.Errorf("invalid verifyProfileIDEnv")
	}

	authToken := e.bddContext.Args[getOrgAuthTokenKey(chunks[0]+"/"+chunks[1])]

	logger.Info("Multi users test", logfields.WithTotalRequests(totalRequests), logfields.WithConcurrencyRequests(concurrencyReq))

	createPool := bddutil.NewWorkerPool(concurrencyReq, logger)

	createPool.Start()

	for i := 0; i < totalRequests; i++ {
		r := &stressRequest{
			wallerRunner:                 e.walletRunner,
			vpFlowExecutor:               e.walletRunner.NewVPFlowExecutor(false),
			authToken:                    authToken,
			profileID:                    chunks[0],
			profileVersion:               chunks[1],
			initiateOIDC4VPData:          initiateOIDC4VPPayload,
			initiateInteractionURLFormat: initiateInteractionURLFormat,
			retrieveClaimURLFormat:       retrieveClaimURLFormat,
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
