/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"time"

	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
)

type ClaimDataType int16

const (
	ClaimDataTypeClaims = ClaimDataType(0)
	ClaimDataTypeVC     = ClaimDataType(1)
)

type PrepareCredentialsRequest struct {
	TxID                    string
	ClaimData               map[string]interface{}
	IssuerDID               string
	SubjectDID              string
	CredentialConfiguration *TxCredentialConfiguration

	IssuerID      string
	IssuerVersion string
}

type TxCredentialConfiguration struct {
	ID                        string
	CredentialTemplate        *profileapi.CredentialTemplate
	OIDCCredentialFormat      vcsverifiable.OIDCFormat
	ClaimEndpoint             string
	ClaimDataID               string
	ClaimDataType             ClaimDataType
	CredentialName            string
	CredentialDescription     string
	CredentialExpiresAt       *time.Time
	PreAuthCodeExpiresAt      *time.Time
	CredentialConfigurationID string
	// AuthorizationDetails may be defined on Authorization Request via using "authorization_details" parameter.
	// If "scope" param is used, this field will stay empty.
	AuthorizationDetails           *AuthorizationDetails
	CredentialComposeConfiguration *CredentialComposeConfiguration
}

type CredentialComposeConfiguration struct {
	IDTemplate         string `json:"id_template"`
	OverrideIssuer     bool   `json:"override_issuer"`
	OverrideSubjectDID bool   `json:"override_subject_did"`
}

// AuthorizationDetails represents the domain model for Authorization Details request.
// This object is used to convey the details about the Credentials the Wallet wants to obtain.
//
// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.1
type AuthorizationDetails struct {
	Type                      string
	Format                    vcsverifiable.OIDCFormat
	Locations                 []string
	CredentialConfigurationID string
	CredentialDefinition      *CredentialDefinition
	CredentialIdentifiers     []string
}

func (ad *AuthorizationDetails) ToDTO() common.AuthorizationDetails {
	var credentialDefinition *common.CredentialDefinition
	if cd := ad.CredentialDefinition; cd != nil {
		credentialDefinition = &common.CredentialDefinition{
			Context:           &cd.Context,
			CredentialSubject: &cd.CredentialSubject,
			Type:              cd.Type,
		}
	}

	return common.AuthorizationDetails{
		CredentialConfigurationId: &ad.CredentialConfigurationID,
		CredentialDefinition:      credentialDefinition,
		CredentialIdentifiers:     lo.ToPtr(ad.CredentialIdentifiers),
		Format:                    lo.ToPtr(string(ad.Format)),
		Locations:                 &ad.Locations,
		Type:                      ad.Type,
	}
}

// CredentialDefinition contains the detailed description of the credential type.
type CredentialDefinition struct {
	// For ldp_vc only. Array as defined in https://www.w3.org/TR/vc-data-model/#contexts.
	Context           []string
	CredentialSubject map[string]interface{}
	Type              []string
}

// ClaimData represents user claims in pre-auth code flow.
type ClaimData struct {
	EncryptedData *dataprotect.EncryptedData `json:"encrypted_data"`
}
