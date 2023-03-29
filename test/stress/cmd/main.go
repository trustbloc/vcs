package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/bluele/gcache"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

var results = gcache.New(100).LRU().Build()
var logger = log.New("stress-test-cmd")

func main() {
	e := echo.New()
	hostName, _ := os.Hostname()

	e.POST("/run", func(c echo.Context) error {
		var cfg request

		c.Response().Header().Set("node", hostName)

		err := json.NewDecoder(c.Request().Body).Decode(&cfg)
		if err != nil {
			return err
		}

		id := uuid.NewString()

		if cfg.ID != "" {
			v, _ := results.Get(cfg.ID)

			if v != nil {
				return c.String(http.StatusConflict, "job already running on this node")
			}

			id = cfg.ID
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

			_ = results.Set(id, testRunResult)

			res, err2 := stress.NewStressRun(&cfg.Config).Run(context.Background())

			now := time.Now().UTC()
			testRunResult.Result = res
			testRunResult.FinishedAt = &now

			if err2 != nil {
				logger.Error(fmt.Sprintf("got error %v for run id %v",
					err2, id))

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
		}()

		return c.String(200, id)
	})

	e.GET("/run/:id", func(c echo.Context) error {
		item, _ := results.Get(c.Param("id"))

		return c.JSON(200, item)
	})

	if errStart := e.Start(os.Getenv("API_ADDRESS")); errStart != nil {
		panic(errStart)
	}
}
