package main

import (
	"time"

	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

type runResult struct {
	Errors      []string       `json:"errors"`
	ErrorsCount int            `json:"errors_count"`
	State       string         `json:"state"`
	StartedAt   time.Time      `json:"started_at"`
	FinishedAt  *time.Time     `json:"finished_at"`
	Result      *stress.Result `json:"_raw_result"`
	Metrics     []metric       `json:"__metrics"`
	HostName    string         `json:"host_name"`
	//PerCredentialData map[string]*stress.PerCredentialData `json:"per_credential_data"`
}

type metric struct {
	Name string `json:"name,omitempty"`
	Avg  string `json:"avg"`
	Max  string `json:"max"`
	Min  string `json:"min"`
}

type request struct {
	ID string `json:"id"`
	stress.Config
}

type clusterResult struct {
	Id    string            `json:"id"`
	Nodes map[string]string `json:"nodes"`
}

type combinedResult struct {
	TotalRate       int                       `json:"total_rate"`
	TotalNodes      int                       `json:"total_nodes"`
	TotalRequests   int                       `json:"total_requests"`
	TotalErrors     int                       `json:"total_errors"`
	GroupedErrors   map[string]int            `json:"grouped_errors"`
	CombinedMetrics map[string]metric         `json:"combined_metrics"`
	PerRunnerInfo   map[string]*perRunnerInfo `json:"per_runner_info"`
	IsFinished      bool                      `json:"is_finished"`
}

type perRunnerInfo struct {
	RawMetrics   []*stress.Metric `json:"raw_metrics"`
	ErrorCount   int              `json:"error_count"`
	RequestCount int              `json:"request_count"`
	Rate         int              `json:"rate"`
	State        string           `json:"state"`
	ResultError  *string          `json:"result_error"`
}
