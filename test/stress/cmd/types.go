package main

import (
	"time"

	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

type runResult struct {
	Error      string         `json:"error"`
	State      string         `json:"state"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at"`
	Result     *stress.Result `json:"_raw_result"`
	Metrics    []metric       `json:"__metrics"`
	HostName   string         `json:"host_name"`
}

type metric struct {
	Name string
	Avg  string
	Max  string
	Min  string
}

type request struct {
	ID string `json:"id"`
	stress.Config
}
