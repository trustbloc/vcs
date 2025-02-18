/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type RFCError[T ~string] struct {
	ErrorCode            T
	ErrorComponent       Component
	Operation            string
	IncorrectValue       string
	HTTPStatus           int
	Err                  error
	usePublicAPIResponse bool
}

// RFCErrorJSON is a helper struct for JSON encoding/decoding of RFCError.
type RFCErrorJSON[T comparable] struct {
	ErrorCode       T         `json:"error"`
	Component       Component `json:"component,omitempty"`
	Operation       string    `json:"operation,omitempty"`
	IncorrectValue  string    `json:"incorrect_value,omitempty"`
	HTTPStatusField int       `json:"http_status,omitempty"`
	Description     string    `json:"error_description,omitempty"`
}

func (e *RFCError[T]) MarshalJSON() ([]byte, error) {
	if e.usePublicAPIResponse {
		return json.Marshal(&RFCErrorJSON[T]{
			ErrorCode:   e.ErrorCode,
			Description: e.getDescription(),
		})
	}

	return json.Marshal(&RFCErrorJSON[T]{
		ErrorCode:       e.ErrorCode,
		Component:       e.ErrorComponent,
		Operation:       e.Operation,
		IncorrectValue:  e.IncorrectValue,
		HTTPStatusField: e.HTTPStatus,
		Description:     e.Err.Error(),
	})
}

func (e *RFCError[T]) UnmarshalJSON(b []byte) error {
	var data RFCErrorJSON[T]

	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	e.ErrorCode = data.ErrorCode
	e.ErrorComponent = data.Component
	e.Operation = data.Operation
	e.IncorrectValue = data.IncorrectValue
	e.HTTPStatus = data.HTTPStatusField
	e.Err = errors.New(data.Description)

	return nil
}

func (e *RFCError[T]) Error() string {
	return e.getDescription()
}

func (e *RFCError[T]) getDescription() string {
	var description []string

	if e.ErrorComponent != "" {
		description = append(description, fmt.Sprintf("component: %s", e.ErrorComponent))
	}

	if e.Operation != "" {
		description = append(description, fmt.Sprintf("operation: %s", e.Operation))
	}

	if e.IncorrectValue != "" {
		description = append(description, fmt.Sprintf("incorrect value: %s", e.IncorrectValue))
	}

	if e.HTTPStatus != 0 {
		description = append(description, fmt.Sprintf("http status: %d", e.HTTPStatus))
	}

	return fmt.Sprintf("%s[%s]: %v", e.ErrorCode, strings.Join(description, "; "), e.Err)
}

func (e *RFCError[T]) WithComponent(component Component) *RFCError[T] {
	e.ErrorComponent = component

	return e
}

func (e *RFCError[T]) WithOperation(operation string) *RFCError[T] {
	e.Operation = operation

	return e
}

func (e *RFCError[T]) WithIncorrectValue(incorrectValue string) *RFCError[T] {
	e.IncorrectValue = incorrectValue

	return e
}

func (e *RFCError[T]) WithHTTPStatusField(httpStatus int) *RFCError[T] {
	e.HTTPStatus = httpStatus

	return e
}

func (e *RFCError[T]) WithErrorPrefix(errPrefix string) *RFCError[T] {
	e.Err = fmt.Errorf("%s: %w", errPrefix, e.Err)

	return e
}

func (e *RFCError[T]) UsePublicAPIResponse() *RFCError[T] {
	e.usePublicAPIResponse = true

	return e
}

func (e *RFCError[T]) Code() string {
	return string(e.ErrorCode)
}

func (e *RFCError[T]) Component() string {
	return string(e.ErrorComponent)
}

func (e *RFCError[T]) Unwrap() error {
	return e.Err
}
