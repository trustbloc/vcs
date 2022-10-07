/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddutil

import (
	"sync"

	"github.com/trustbloc/edge-core/pkg/log"
)

// Request is a request that's submitted to the worker pool for processing.
type Request interface {
	Invoke() (interface{}, error)
}

// Response is the response for an individual request.
type Response struct {
	Request
	Resp interface{}
	Err  error
}

// WorkerPool manages a pool of workers that processes requests concurrently and, at the end, gathers the responses.
type WorkerPool struct {
	workers   []*worker
	reqChan   chan Request
	respChan  chan *Response
	wgResp    sync.WaitGroup
	wg        *sync.WaitGroup
	responses []*Response
	logger    log.Logger
}

// NewWorkerPool returns a new worker pool with the given number of workers.
func NewWorkerPool(num int, logger log.Logger) *WorkerPool {
	reqChan := make(chan Request)
	respChan := make(chan *Response)
	workers := make([]*worker, num)

	wg := &sync.WaitGroup{}

	for i := 0; i < num; i++ {
		workers[i] = newWorker(reqChan, respChan, wg)
	}

	return &WorkerPool{
		workers:  workers,
		reqChan:  reqChan,
		respChan: respChan,
		wg:       wg,
		logger:   logger,
	}
}

// Start starts all the workers and listens for responses.
func (p *WorkerPool) Start() {
	p.wgResp.Add(1)

	go p.listen()

	p.wg.Add(len(p.workers))

	for _, w := range p.workers {
		go w.start()
	}
}

// Stop stops the workers in the pool and stops listening for responses.
func (p *WorkerPool) Stop() {
	close(p.reqChan)

	p.logger.Infof("Waiting %d for workers to finish...", len(p.workers))

	p.wg.Wait()

	p.logger.Infof("... all %d workers finished.", len(p.workers))

	close(p.respChan)

	p.logger.Infof("Waiting for listener to finish...")

	p.wgResp.Wait()

	p.logger.Infof("... listener finished.")
}

// Submit submits a request for processing.
func (p *WorkerPool) Submit(req Request) {
	p.reqChan <- req
}

// Responses contains the responses after the pool is stopped.
func (p *WorkerPool) Responses() []*Response {
	return p.responses
}

func (p *WorkerPool) listen() {
	for resp := range p.respChan {
		p.responses = append(p.responses, resp)
	}

	p.logger.Infof("Exiting listener")

	p.wgResp.Done()
}

type worker struct {
	reqChan  chan Request
	respChan chan *Response
	wg       *sync.WaitGroup
}

func newWorker(reqChan chan Request, respChan chan *Response, wg *sync.WaitGroup) *worker {
	return &worker{
		reqChan:  reqChan,
		respChan: respChan,
		wg:       wg,
	}
}

func (w *worker) start() {
	for req := range w.reqChan {
		data, err := req.Invoke()
		w.respChan <- &Response{
			Request: req,
			Resp:    data,
			Err:     err,
		}
	}

	w.wg.Done()
}
