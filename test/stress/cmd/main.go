package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/bluele/gcache"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

var results = gcache.New(100).LRU().Build()

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
			testRunResult.Error = err2
			testRunResult.Result = res
			testRunResult.FinishedAt = &now

			if testRunResult.Error != nil {
				testRunResult.State = "failed"
			} else {
				testRunResult.State = "complete"
			}

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