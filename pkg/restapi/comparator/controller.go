/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comparator

import (
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation"
)

// New returns new controller instance.
func New(config *operation.Config) (*Controller, error) {
	comparatorService, err := operation.New(config)
	if err != nil {
		return nil, err
	}

	return &Controller{
		handlers: comparatorService.GetRESTHandlers(),
	}, nil
}

// Controller contains handlers for controller.
type Controller struct {
	handlers []support.Handler
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []support.Handler {
	return c.handlers
}
