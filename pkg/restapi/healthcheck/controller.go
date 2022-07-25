/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package healthcheck

import (
	"github.com/trustbloc/vcs/pkg/internal/common/support"
	"github.com/trustbloc/vcs/pkg/restapi/healthcheck/operation"
)

// New returns new controller instance.
func New() *Controller {
	var allHandlers []support.Handler

	rpService := operation.New()

	handlers := rpService.GetRESTHandlers()

	allHandlers = append(allHandlers, handlers...)

	return &Controller{handlers: allHandlers}
}

// Controller contains handlers for controller.
type Controller struct {
	handlers []support.Handler
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []support.Handler {
	return c.handlers
}
