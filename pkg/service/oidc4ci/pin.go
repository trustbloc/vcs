package oidc4ci

import (
	"fmt"
	"math/rand"
	"strings"
)

const (
	maxNumber = 10
)

type PinGenerator struct {
}

func NewPinGenerator() *PinGenerator {
	return &PinGenerator{}
}

func (p *PinGenerator) Generate() string {
	var finalPin strings.Builder

	for i := 0; i < 6; i++ {
		finalPin.WriteString(fmt.Sprint(rand.Int31n(maxNumber))) //nolint:gosec
	}

	return finalPin.String()
}

func (p *PinGenerator) Validate(otpKey string, got string) bool { // in future there will be more implementations
	return otpKey == got
}
