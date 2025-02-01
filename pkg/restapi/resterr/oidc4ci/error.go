/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

// oidc4ciErrorCode is OIDC4CI-specific error codes, that are not declared in RFC specifications.
type oidc4ciErrorCode string

const (
	// invalidNotificationID - the notification_id in the Notification Request was invalid.
	//
	// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-10.3-3.1.2.1
	invalidNotificationID oidc4ciErrorCode = "invalid_notification_id"

	// invalidNotificationRequest - the Notification Request is missing a required parameter,
	// includes an unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed.
	//
	// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-10.3-3.1.2.2
	invalidNotificationRequest oidc4ciErrorCode = "invalid_notification_request"

	// invalidCredentialRequest - the Credential Request is missing a required parameter,
	// includes an unsupported parameter or parameter value, repeats the same parameter,
	// or is otherwise malformed.
	//
	// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.3.1.2-3.1.2.1
	invalidCredentialRequest oidc4ciErrorCode = "invalid_credential_request" //nolint:gosec

	// unsupportedCredentialType - requested Credential type is not supported.
	//
	// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.3.1.2-3.1.2.2
	unsupportedCredentialType oidc4ciErrorCode = "unsupported_credential_type"

	// unsupportedCredentialFormat - requested Credential format is not supported.
	//
	// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.3.1.2-3.1.2.3
	unsupportedCredentialFormat oidc4ciErrorCode = "unsupported_credential_format"

	// invalidProof - the proof in the Credential Request is invalid.
	// The proof field is not present or the provided key proof
	// is invalid or not bound to a nonce provided by the Credential Issuer.
	//
	// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.3.1.2-3.1.2.4
	invalidProof oidc4ciErrorCode = "invalid_proof"

	// invalidEncryptionParameters - error occurs when the encryption parameters in the Credential Request
	// are either invalid or missing. In the latter case, it indicates that the Credential Issuer
	// requires the Credential Response to be sent encrypted, but the Credential Request
	// does not contain the necessary encryption parameters.
	//
	// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.3.1.2-3.1.2.5
	invalidEncryptionParameters oidc4ciErrorCode = "invalid_encryption_parameters"

	// forbidden proprietary error code. Not described by any specification that VCS supports.
	forbidden oidc4ciErrorCode = "forbidden"

	// unauthorized proprietary error code. Not described by any specification that VCS supports.
	unauthorized oidc4ciErrorCode = "unauthorized"

	// badRequest proprietary error code. Not described by any specification that VCS supports.
	badRequest oidc4ciErrorCode = "bad_request"

	// expiredAckID proprietary error code. Not described by any specification that VCS supports.
	expiredAckID oidc4ciErrorCode = "expired_ack_id"

	// notFound proprietary error code. Not described by any specification that VCS supports.
	notFound oidc4ciErrorCode = "not_found"
)

// Error represents OIDC4CI error.
type Error = resterr.RFCError[oidc4ciErrorCode]
