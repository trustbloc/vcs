/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/joho/godotenv"
	"github.com/samber/lo"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

var logger = log.New("stress-test-cmd")

const (
	orchestratorKey = "stress:nodes"
)

func main() {
	_ = godotenv.Load(".env")
	e := echo.New()
	hostName := getNodeName()
	apiAddress := os.Getenv("API_ADDRESS")
	k8SvcName := os.Getenv("K8_HEADLESS_SVC")
	port := strings.Split(apiAddress, ":")[1]

	var redisTls *tls.Config
	tlsDisabled, _ := strconv.ParseBool(os.Getenv("REDIS_DISABLE_TLS"))
	if !tlsDisabled {
		redisTls = &tls.Config{}
	}

	rdb := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:     strings.Split(os.Getenv("REDIS_URL"), ","),
		Password:  os.Getenv("REDIS_PASSWORD"),
		DB:        0,
		TLSConfig: redisTls,
	})

	if redisErr := rdb.Ping(context.TODO()).Err(); redisErr != nil {
		panic(redisErr)
	}

	go func() {
		for context.Background().Err() == nil {
			var b strings.Builder
			b.WriteString(fmt.Sprintf("http://%v", hostName))
			if k8SvcName != "" {
				b.WriteString(fmt.Sprintf(".%v", k8SvcName))
			}
			b.WriteString(fmt.Sprintf(":%v", port))
			if err := rdb.HSet(context.Background(), orchestratorKey, hostName, b.String()).Err(); err != nil {
				panic(err)
			}

			logger.Info(fmt.Sprintf("node registered in cluster mode with url: %v", b.String()))

			time.Sleep(30 * time.Second)
		}
	}()

	e.GET("/ready", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	e.GET("/nodes", func(c echo.Context) error {
		members, err := getClusterMembers(c.Request().Context(), rdb)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		return c.JSON(http.StatusOK, members)
	})

	e.POST("/run", func(c echo.Context) error {
		var cfg request

		c.Response().Header().Set("node", hostName)
		err := json.NewDecoder(c.Request().Body).Decode(&cfg)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		clusterMembers, err := getClusterMembers(c.Request().Context(), rdb)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		cfg.ID = uuid.NewString()
		healthyMembers := map[string]string{}
		for member, url := range clusterMembers {
			_, hError := req.Get(url)
			if hError != nil {
				logger.Error(fmt.Sprintf("error checking health for node [%v] and url [%v] with error [%v]",
					member, url, hError))

				_ = rdb.HDel(c.Request().Context(), orchestratorKey, member)
				continue
			}

			healthyMembers[member] = url
		}

		if len(healthyMembers) == 0 {
			return c.String(http.StatusBadRequest, errors.New("no healthy cluster members").Error())
		}

		cfg.ConcurrentRequests /= len(healthyMembers)

		res := &clusterResult{
			Id:        cfg.ID,
			Nodes:     map[string]string{},
			TotalRate: cfg.ConcurrentRequests * len(healthyMembers),
		}

		for member, url := range healthyMembers {
			var resultId string
			resp, err := req.R().SetBodyJsonMarshal(cfg).
				Post(fmt.Sprintf("%v/internal/run", url))

			if err != nil {
				return fmt.Errorf("can not schedule job on %v with error %w", member, err)
			}

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("can not schedule job on %v with status code %v", member, resp.StatusCode)
			}

			resultId = resp.String()
			res.Nodes[member] = resultId
			time.Sleep(2 * time.Second)
		}

		b, err := json.Marshal(res)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		rdb.Set(c.Request().Context(), getClusterResultKey(res.Id), b, 3*time.Hour)

		return c.JSON(200, res)
	})

	e.POST("/internal/run", func(c echo.Context) error {
		var cfg request
		resultId := uuid.NewString()
		clusterResultKey := getResultKey(resultId)

		err := json.NewDecoder(c.Request().Body).Decode(&cfg)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		cfg.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
		}

		go func() {
			testRunResult := &runResult{
				State:     "running",
				StartedAt: time.Now().UTC(),
				HostName:  hostName,
			}

			b, _ := json.Marshal(testRunResult)
			rdb.Set(context.Background(), clusterResultKey, b, 3*time.Hour)
			res, err2 := stress.NewStressRun(&cfg.Config).Run(context.Background())

			now := time.Now().UTC()
			testRunResult.Result = res
			testRunResult.FinishedAt = &now

			//if testRunResult.Result != nil && !cfg.Detailed {
			//	testRunResult.PerCredentialData = nil
			//}

			if err2 != nil {
				logger.Error(fmt.Sprintf("got error %v for run id %v",
					err2, resultId))

				testRunResult.Errors = []string{fmt.Sprintf("%+v", err2)}
				testRunResult.State = "failed"
			} else {
				testRunResult.State = "complete"
			}

			if res != nil && len(res.Errors) > 0 {
				testRunResult.State = "complete with errors"

				for _, testErr := range res.Errors {
					testRunResult.Errors = append(testRunResult.Errors, fmt.Sprintf("%+v", testErr))
				}
			}

			testRunResult.ErrorsCount = len(testRunResult.Errors)

			if testRunResult.Result != nil {
				for _, v := range testRunResult.Result.Metrics {
					testRunResult.Metrics = append(testRunResult.Metrics, metric{
						Name: v.Name,
						Avg:  v.Avg.String(),
						Max:  v.Max.String(),
						Min:  v.Min.String(),
					})
				}
			}

			b, _ = json.Marshal(testRunResult)
			rdb.Set(context.Background(), clusterResultKey, b, 3*time.Hour)
		}()

		return c.String(http.StatusOK, clusterResultKey)
	})

	e.GET("/run/:id", func(c echo.Context) error {
		item := rdb.Get(c.Request().Context(), getClusterResultKey(c.Param("id")))
		var res clusterResult

		b, err := item.Bytes()
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		if err = json.Unmarshal(b, &res); err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		finalResult := &combinedResult{
			IsFinished:      true,
			TotalNodes:      len(res.Nodes),
			PerRunnerInfo:   map[string]*perRunnerInfo{},
			CombinedMetrics: map[string]metric{},
			GroupedErrors:   map[string]int{},
			TotalRate:       res.TotalRate,
		}

		meticData := map[string]*stress.Metric{}

		for id, resultId := range res.Nodes {
			runnerInfo := &perRunnerInfo{}
			finalResult.PerRunnerInfo[id] = runnerInfo

			runnerResult := rdb.Get(c.Request().Context(), resultId)
			if runnerResult.Err() != nil {
				runnerInfo.ResultError = lo.ToPtr(runnerResult.Err().Error())
				finalResult.IsFinished = false
				continue
			}

			var run runResult
			rb, err := runnerResult.Bytes()
			if err != nil {
				runnerInfo.ResultError = lo.ToPtr(runnerResult.Err().Error())
				finalResult.IsFinished = false
				continue
			}

			if err := json.Unmarshal(rb, &run); err != nil {
				runnerInfo.ResultError = lo.ToPtr(fmt.Errorf("can not unmarshal. %w", err).Error())
				finalResult.IsFinished = false
				continue
			}

			runnerInfo.State = run.State
			if runnerInfo.State == "running" {
				finalResult.IsFinished = false
			}

			runnerInfo.ErrorCount = run.ErrorsCount
			finalResult.TotalErrors += run.ErrorsCount

			if run.Result != nil {
				runnerInfo.RawMetrics = run.Result.Metrics

				runnerInfo.Rate = run.Result.ConcurrentRequests

				runnerInfo.RequestCount = run.Result.UserCount
				finalResult.TotalRequests += run.Result.UserCount

				if len(run.Result.Metrics) > 0 {
					for _, m := range run.Result.Metrics {
						v, ok := meticData[m.Name]
						if !ok {
							cp := *m
							meticData[m.Name] = &cp
							continue
						}

						v.Avg = (v.Avg + m.Avg) / 2
						if v.Min > m.Min {
							v.Min = m.Min
						}
						if v.Max < m.Max {
							v.Max = m.Max
						}
					}
				}

				if len(run.Errors) > 0 {
					for _, errStr := range run.Errors {
						finalResult.GroupedErrors[errStr] += 1
					}
				}
			}
		}

		for k, v := range meticData {
			finalResult.CombinedMetrics[k] = metric{
				Avg: v.Avg.String(),
				Max: v.Max.String(),
				Min: v.Min.String(),
			}
		}

		return c.JSON(200, finalResult)
	})

	if errStart := e.Start(os.Getenv("API_ADDRESS")); errStart != nil {
		panic(errStart)
	}
}
