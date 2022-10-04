/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/openapi.yaml
//go:generate mockgen -destination controller_mocks_test.go -self_package mocks -package devapi -source=controller.go -mock_names verifierProfileService=MockVerifierProfileService,issuerProfileService=MockIssuerProfileService,issueCredentialService=MockIssueCredentialService

package devapi

import (
	"errors"
	"fmt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/labstack/echo/v4"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	apiUtil "github.com/trustbloc/vcs/pkg/restapi/v1/util"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"strings"
	"time"
)

type verifierProfileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Verifier, error)
}

type issuerProfileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error)
}

type issueCredentialService interface {
	IssueCredential(credential *verifiable.Credential,
		issuerSigningOpts []crypto.SigningOpts,
		profile *profileapi.Issuer) (*verifiable.Credential, error)
}

type Config struct {
	VerifierProfileService  verifierProfileService
	IssuerProfileService    issuerProfileService
	IssuerCredentialService issueCredentialService
}

type Controller struct {
	verifierProfileService  verifierProfileService
	issuerProfileService    issuerProfileService
	issuerCredentialService issueCredentialService
}

func NewController(
	config *Config,
) *Controller {
	return &Controller{
		verifierProfileService:  config.VerifierProfileService,
		issuerProfileService:    config.IssuerProfileService,
		issuerCredentialService: config.IssuerCredentialService,
	}
}

// DidConfig requests well-known DID config.
// GET /{profileType}/profiles/{profileID}/well-known/did-config.
func (c *Controller) DidConfig(ctx echo.Context, profileType string, profileID string) error {
	var issuer *profileapi.Issuer

	switch strings.ToLower(profileType) {
	case "verifier":
		c.verifierProfileService.GetProfile(profileID)
	case "issuer":
		if profile, err := c.issuerProfileService.GetProfile(profileID); err != nil {
			return resterr.NewValidationError(resterr.SystemError, "profileID",
				err)
		} else {
			issuer = profile
		}
	default:
		return resterr.NewValidationError(resterr.InvalidValue, "profileType",
			errors.New("profileType should be verifier or issuer"))
	}

	cred, err := c.issuerCredentialService.IssueCredential(&verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			ctx.Request().URL.RequestURI(),
		},
		Types: []string{
			"VerifiableCredential",
			"DomainLinkageCredential",
		},
		Issuer: verifiable.Issuer{
			ID: issuer.ID,
		},
		Issued: util.NewTime(time.Now().UTC()),
		Subject: map[string]interface{}{
			"id":     issuer.ID,
			"origin": fmt.Sprintf("%s://%s", ctx.Request().URL.Scheme, ctx.Request().URL.Hostname()),
		},
	}, nil, issuer)

	if err != nil {
		return err
	}

	return apiUtil.WriteOutput(ctx)(cred, err)
}
