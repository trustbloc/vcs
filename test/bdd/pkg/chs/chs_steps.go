/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package chs

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cucumber/godog"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	bddctx "github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	hubBaseURL = "https://localhost:8095"
)

// NewSteps returns BDD test steps for the confidential storage hub.
func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{ctx: ctx}
}

// Steps BDD test steps for the confidential storage hub.
type Steps struct {
	ctx  *bddctx.BDDContext
	user *user
}

// RegisterSteps for this BDD test.
func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step("^the user requests a new confidential-storage-hub profile$", s.userCreatesProfile)
	gs.Step("^the confidential-storage-hub profile is created$", s.userProfileIsCreated)
}

func (s *Steps) userCreatesProfile() error {
	var err error

	s.user, err = newUser(hubBaseURL, s.ctx.TLSConfig)
	if err != nil {
		return fmt.Errorf("failed to create new user: %w", err)
	}

	err = s.user.requestNewProfile()
	if err != nil {
		return fmt.Errorf("user failed to create a profile: %w", err)
	}

	return nil
}

func (s *Steps) userProfileIsCreated() error {
	fmt.Printf("user profile: %+v", s.user.profile)

	if s.user.profile.ID == "" {
		return errors.New("profile does not have an ID")
	}

	if s.user.profile.Controller == "" {
		return errors.New("profile does not have a controller")
	}

	if s.user.profile.ZCAP == "" {
		return errors.New("profile does not have a zcap")
	}

	zcap, err := parseZCAP(s.user.profile.ZCAP)
	if err != nil {
		return fmt.Errorf("failed to parse profile zcap: %w", err)
	}

	if s.user.controller != zcap.Controller {
		return fmt.Errorf(
			"the user is not the profile's controller: user.controller=%s profile.controller=%s",
			s.user.controller, s.user.profile.Controller,
		)
	}

	if s.user.controller != zcap.Invoker {
		return fmt.Errorf(
			"the user is not the profile's invoker: user.controller=%s profile.controller=%s",
			s.user.controller, s.user.profile.Controller,
		)
	}

	return nil
}

func parseZCAP(encoded string) (*zcapld.Capability, error) {
	deflated, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64URL-decode zcap: %w", err)
	}

	pump, err := gzip.NewReader(bytes.NewReader(deflated))
	if err != nil {
		return nil, fmt.Errorf("failed to init gzip reader: %w", err)
	}

	inflated := bytes.NewBuffer(nil)

	_, err = inflated.ReadFrom(pump)
	if err != nil {
		return nil, fmt.Errorf("failed to gunzip zcap: %w", err)
	}

	zcap, err := zcapld.ParseCapability(inflated.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to parse zcap: %w", err)
	}

	return zcap, nil
}
