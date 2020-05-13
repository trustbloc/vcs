/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"github.com/trustbloc/edge-service/pkg/restapi/verifier/operation"
)

// New returns new controller instance.
func New(config *operation.Config) *Controller {
	var allHandlers []operation.Handler

	holderService := operation.New(config)

	handlers := holderService.GetRESTHandlers()

	allHandlers = append(allHandlers, handlers...)

	return &Controller{handlers: allHandlers}
}

// Controller contains handlers for controller
type Controller struct {
	handlers []operation.Handler
}

// GetOperations returns all controller endpoints
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
