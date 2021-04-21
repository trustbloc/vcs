/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"github.com/trustbloc/edge-service/pkg/restapi/did/operation"
)

// New returns new controller instance.
func New(config *operation.Config) (*Controller, error) {
	var allHandlers []operation.Handler

	didService, err := operation.New(config)
	if err != nil {
		return nil, err
	}

	handlers := didService.GetRESTHandlers()
	allHandlers = append(allHandlers, handlers...)

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
