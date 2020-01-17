/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
)

// New returns new controller instance.
func New() (*Controller, error) {
	var allHandlers []operation.Handler

	issueService := operation.New()
	allHandlers = append(allHandlers, issueService.GetRESTHandlers()...)

	return &Controller{handlers: allHandlers}, nil
}

// Controller contains handlers for controller
type Controller struct {
	handlers []operation.Handler
}

// GetOperations returns all controller endpoints
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
