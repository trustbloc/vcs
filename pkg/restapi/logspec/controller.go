/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logspec

import (
	"github.com/trustbloc/edge-service/pkg/restapi/logspec/operation"
)

// New returns a new controller instance.
func New() *Controller {
	return &Controller{handlers: operation.GetRESTHandlers()}
}

// Controller contains handlers for controller
type Controller struct {
	handlers []operation.Handler
}

// GetOperations returns all controller endpoints
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
