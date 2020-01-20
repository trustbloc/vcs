/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
)

// New returns new controller instance.
func New(provider storage.Provider, client operation.Client) (*Controller, error) {
	var allHandlers []operation.Handler

	vcService, err := operation.New(provider, client)
	if err != nil {
		return nil, err
	}

	allHandlers = append(allHandlers, vcService.GetRESTHandlers()...)

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
