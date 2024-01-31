/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"errors"

	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func ValidateAuthorizationDetails(
	authorizationDetails []common.AuthorizationDetails) (*oidc4ci.AuthorizationDetails, error) {
	if len(authorizationDetails) != 1 {
		return nil, resterr.NewOIDCError("invalid_request",
			errors.New("only single authorization_details supported"))
	}

	ad := authorizationDetails[0]

	if ad.Type != "openid_credential" {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "authorization_details.type",
			errors.New("type should be 'openid_credential'"))
	}

	oidcCredentialFormat := lo.FromPtr(ad.Format)
	credentialConfigurationID := lo.FromPtr(ad.CredentialConfigurationId)

	mapped := &oidc4ci.AuthorizationDetails{
		Type:                      ad.Type,
		Locations:                 lo.FromPtr(ad.Locations),
		CredentialConfigurationID: "",
		Format:                    "",
		CredentialDefinition:      nil,
	}

	switch {
	case credentialConfigurationID != "": // Priority 1. Based on credentialConfigurationID.
		mapped.CredentialConfigurationID = credentialConfigurationID
	case oidcCredentialFormat != "": // Priority 2. Based on credentialFormat.
		vcsCredentialFormat, err := common.ValidateVCFormat(common.VCFormat(oidcCredentialFormat))
		if err != nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "authorization_details.format", err)
		}

		mapped.Format = vcsCredentialFormat

		if ad.CredentialDefinition == nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue,
				"authorization_details.credential_definition", errors.New("not supplied"))
		}

		mapped.CredentialDefinition = &oidc4ci.CredentialDefinition{
			Context:           lo.FromPtr(ad.CredentialDefinition.Context),
			CredentialSubject: lo.FromPtr(ad.CredentialDefinition.CredentialSubject),
			Type:              ad.CredentialDefinition.Type,
		}
	default:
		return nil, resterr.NewValidationError(resterr.InvalidValue,
			"authorization_details.credential_configuration_id",
			errors.New("neither credentialFormat nor credentialConfigurationID supplied"))
	}

	return mapped, nil
}
