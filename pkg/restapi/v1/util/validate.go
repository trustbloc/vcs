/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

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

func ValidateAuthorizationDetails(ad *common.AuthorizationDetails) (*oidc4ci.AuthorizationDetails, error) {
	if ad.Type != "openid_credential" {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "authorization_details.type",
			errors.New("type should be 'openid_credential'"))
	}

	mapped := &oidc4ci.AuthorizationDetails{
		Type:      ad.Type,
		Types:     ad.Types,
		Locations: lo.FromPtr(ad.Locations),
	}

	if ad.Format != nil {
		vcFormat, err := common.ValidateVCFormat(common.VCFormat(*ad.Format))
		if err != nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, "authorization_details.format", err)
		}

		mapped.Format = vcFormat
	}

	return mapped, nil
}
