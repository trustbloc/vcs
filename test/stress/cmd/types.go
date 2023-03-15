package main

import (
	"time"

	"github.com/trustbloc/vcs/test/stress/pkg/stress"
)

type runResult struct {
	Error      error          `json:"error"`
	State      string         `json:"state"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at"`
	Result     *stress.Result `json:"_raw_result"`
	Metrics    []metric       `json:"__metrics"`
}

type metric struct {
	Name string
	Avg  string
	Max  string
	Min  string
}
