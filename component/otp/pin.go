/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package otp

import (
	"fmt"
	"math/rand"
	"strings"
)

const (
	maxNumber = 10
)

// PinGenerator implements logic for generating and verifying otp pin codes.
type PinGenerator struct {
}

// NewPinGenerator creates a new instance of PinGenerator.
func NewPinGenerator() *PinGenerator {
	return &PinGenerator{}
}

// Generate generates a new pin based on challenge
func (p *PinGenerator) Generate(_ string) string {
	var finalPin strings.Builder

	for i := 0; i < 6; i++ {
		finalPin.WriteString(fmt.Sprint(rand.Int31n(maxNumber))) //nolint:gosec
	}

	return finalPin.String()
}

// Validate validates pin
func (p *PinGenerator) Validate(challenge string, userInput string) bool { // in future there will be more implementations
	return challenge == userInput
}
