/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lifecycle

import (
	"sync/atomic"

	"github.com/pkg/errors"

	"github.com/trustbloc/edge-core/pkg/log"

	orberrors "github.com/trustbloc/orb/pkg/errors"
)

var logger = log.New("lifecycle")

// ErrNotStarted indicates that an attempt was made to invoke a service that has not been started
// or is still in the process of starting.
var ErrNotStarted = orberrors.NewTransient(errors.New("service has not started"))

// State is the state of the service.
type State = uint32

const (
	// StateNotStarted indicates that the service has not been started.
	StateNotStarted State = 0
	// StateStarting indicates that the service is in the process of starting.
	StateStarting State = 1
	// StateStarted indicates that the service has been started.
	StateStarted State = 2
	// StateStopped indicates that the service has been stopped.
	StateStopped State = 3
)

type options struct {
	start func()
	stop  func()
}

// Lifecycle implements the lifecycle of a service, i.e. Start and Stop.
type Lifecycle struct {
	*options
	name  string
	state uint32
}

// Opt sets a Lifecycle option.
type Opt func(opts *options)

// WithStart sets the start function which is invoked when Start() is called.
func WithStart(start func()) Opt {
	return func(opts *options) {
		opts.start = start
	}
}

// WithStop sets the stop function which is invoked when Stop() is called.
func WithStop(stop func()) Opt {
	return func(opts *options) {
		opts.stop = stop
	}
}

// New returns a new Lifecycle.
func New(name string, opts ...Opt) *Lifecycle {
	options := &options{
		start: func() {},
		stop:  func() {},
	}

	for _, opt := range opts {
		opt(options)
	}

	return &Lifecycle{
		options: options,
		name:    name,
	}
}

// Start starts the service.
func (h *Lifecycle) Start() {
	if !atomic.CompareAndSwapUint32(&h.state, StateNotStarted, StateStarting) {
		logger.Debugf("[%s] Service already started", h.name)

		return
	}

	logger.Debugf("[%s] Starting service ...", h.name)

	h.start()

	logger.Debugf("[%s] ... service started", h.name)

	atomic.StoreUint32(&h.state, StateStarted)
}

// Stop stops the service.
func (h *Lifecycle) Stop() {
	if !atomic.CompareAndSwapUint32(&h.state, StateStarted, StateStopped) {
		logger.Debugf("[%s] Service already stopped", h.name)

		return
	}

	logger.Debugf("[%s] Stopping service ...", h.name)

	h.stop()

	logger.Debugf("[%s] ... service stopped", h.name)
}

// State returns the state of the service.
func (h *Lifecycle) State() State {
	return atomic.LoadUint32(&h.state)
}
