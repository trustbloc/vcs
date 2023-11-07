/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"errors"
	"fmt"
	"net/http"
)

type ErrorCode string

//nolint:gosec
const (
	SystemError                      ErrorCode = "system-error"
	Unauthorized                     ErrorCode = "unauthorized"
	InvalidValue                     ErrorCode = "invalid-value"
	AlreadyExist                     ErrorCode = "already-exist"
	DoesntExist                      ErrorCode = "doesnt-exist"
	ConditionNotMet                  ErrorCode = "condition-not-met"
	OIDCError                        ErrorCode = "oidc-error"
	OIDCTxNotFound                   ErrorCode = "oidc-tx-not-found"
	OIDCPreAuthorizeDoesNotExpectPin ErrorCode = "oidc-pre-authorize-does-not-expect-pin"
	OIDCPreAuthorizeExpectPin        ErrorCode = "oidc-pre-authorize-expect-pin"
	OIDCPreAuthorizeInvalidPin       ErrorCode = "oidc-pre-authorize-invalid-pin"
	OIDCPreAuthorizeInvalidClientID  ErrorCode = "oidc-pre-authorize-invalid-client-id"
	OIDCCredentialFormatNotSupported ErrorCode = "oidc-credential-format-not-supported"
	OIDCCredentialTypeNotSupported   ErrorCode = "oidc-credential-type-not-supported"
	OIDCClientAuthenticationFailed   ErrorCode = "oidc-client-authentication-failed"
	InvalidOrMissingProofOIDCErr     ErrorCode = "invalid_or_missing_proof"

	ProfileNotFound                 ErrorCode = "profile-not-found"
	ProfileInactive                 ErrorCode = "profile-inactive"
	TransactionNotFound             ErrorCode = "transaction-not-found"
	CredentialTemplateNotFound      ErrorCode = "credential-template-not-found"
	PresentationVerificationFailed  ErrorCode = "presentation-verification-failed"
	DuplicatePresentationID         ErrorCode = "duplicate-presentation-id"
	PresentationDefinitionMismatch  ErrorCode = "presentation-definition-mismatch"
	ClaimsNotReceived               ErrorCode = "claims-not-received"
	ClaimsNotFound                  ErrorCode = "claims-not-found"
	ClaimsValidationErr             ErrorCode = "invalid-claims"
	DataNotFound                    ErrorCode = "data-not-found"
	OpStateKeyDuplication           ErrorCode = "op-state-key-duplication"
	CredentialTemplateNotConfigured ErrorCode = "credential-template-not-configured"
	CredentialTemplateIDRequired    ErrorCode = "credential-template-id-required"
	AuthorizedCodeFlowNotSupported  ErrorCode = "authorized-code-flow-not-supported"
	ResponseTypeMismatch            ErrorCode = "response-type-mismatch"
	InvalidScope                    ErrorCode = "invalid-scope"
	CredentialTypeNotSupported      ErrorCode = "credential-type-not-supported"
	CredentialFormatNotSupported    ErrorCode = "credential-format-not-supported"
	VCOptionsNotConfigured          ErrorCode = "vc-options-not-configured"
	InvalidIssuerURL                ErrorCode = "invalid-issuer-url"
	InvalidStateTransition          ErrorCode = "invalid-state-transition"
)

type Component = string

//nolint:gosec
const (
	IssuerSvcComponent          Component = "issuer.service"
	IssuerProfileSvcComponent   Component = "issuer.profile-service"
	IssueCredentialSvcComponent Component = "issuer.issue-credential-service"
	IssuerOIDC4ciSvcComponent   Component = "issuer.oidc4ci-service"

	VerifierVerifyCredentialSvcComponent  Component = "verifier.verify-credential-service"
	VerifierOIDC4vpSvcComponent           Component = "verifier.oidc4vp-service"
	VerifierProfileSvcComponent           Component = "verifier.profile-service"
	VerifierTxnMgrComponent               Component = "verifier.txn-mgr"
	VerifierVCSignerComponent             Component = "verifier.vc-signer"
	VerifierKMSRegistryComponent          Component = "verifier.kms-registry"
	VerifierPresentationVerifierComponent Component = "verifier.presentation-verifier"
	VerifierDataIntegrityVerifier         Component = "verifier.data-integrity-verifier"

	ClientIDSchemeSvcComponent             Component = "client-id-scheme-service"
	ClientManagerComponent                 Component = "client-manager"
	WellKnownSvcComponent                  Component = "well-known-service"
	DataProtectorComponent                 Component = "data-protector"
	ClaimDataStoreComponent                Component = "claim-data-store"
	TransactionStoreComponent              Component = "transaction-store"
	CryptoJWTSignerComponent               Component = "crypto-jwt-signer"
	CredentialOfferReferenceStoreComponent Component = "credential-offer-reference-store"
	RedisComponent                         Component = "redis-service"
)

var (
	ErrDataNotFound                    = NewCustomError(DataNotFound, errors.New("data not found"))
	ErrOpStateKeyDuplication           = NewCustomError(OpStateKeyDuplication, errors.New("op state key duplication"))
	ErrProfileInactive                 = NewCustomError(ProfileInactive, errors.New("profile not active"))
	ErrCredentialTemplateNotFound      = NewCustomError(CredentialTemplateNotFound, errors.New("credential template not found"))           //nolint:lll
	ErrCredentialTemplateNotConfigured = NewCustomError(CredentialTemplateNotConfigured, errors.New("credential template not configured")) //nolint:lll
	ErrCredentialTemplateIDRequired    = NewCustomError(CredentialTemplateIDRequired, errors.New("credential template ID is required"))    //nolint:lll
	ErrAuthorizedCodeFlowNotSupported  = NewCustomError(AuthorizedCodeFlowNotSupported, errors.New("authorized code flow not supported"))  //nolint:lll
	ErrResponseTypeMismatch            = NewCustomError(ResponseTypeMismatch, errors.New("response type mismatch"))
	ErrInvalidScope                    = NewCustomError(InvalidScope, errors.New("invalid scope"))
	ErrCredentialTypeNotSupported      = NewCustomError(CredentialTypeNotSupported, errors.New("credential type not supported"))     //nolint:lll
	ErrCredentialFormatNotSupported    = NewCustomError(CredentialFormatNotSupported, errors.New("credential format not supported")) //nolint:lll
	ErrVCOptionsNotConfigured          = NewCustomError(VCOptionsNotConfigured, errors.New("vc options not configured"))
	ErrInvalidIssuerURL                = NewCustomError(InvalidIssuerURL, errors.New("invalid issuer url"))
)

func (c ErrorCode) Name() string {
	return string(c)
}

type CustomError struct {
	Code            ErrorCode
	IncorrectValue  string
	FailedOperation string
	Component       Component
	Err             error
}

func NewSystemError(component Component, failedOperation string, err error) *CustomError {
	return &CustomError{
		Code:            SystemError,
		FailedOperation: failedOperation,
		Component:       component,
		Err:             err,
	}
}

func NewValidationError(code ErrorCode, incorrectValue string, err error) *CustomError {
	return &CustomError{
		Code:           code,
		IncorrectValue: incorrectValue,
		Err:            err,
	}
}

func NewUnauthorizedError(err error) *CustomError {
	return &CustomError{
		Code: Unauthorized,
		Err:  err,
	}
}

func NewCustomError(code ErrorCode, err error) *CustomError {
	return &CustomError{
		Code: code,
		Err:  err,
	}
}

func NewOIDCError(message string, raw error) *CustomError {
	return &CustomError{
		Code:      OIDCError,
		Component: message,
		Err:       raw,
	}
}

func (e *CustomError) Error() string {
	if e.Code == SystemError {
		return fmt.Sprintf("%s[%s, %s]: %v", SystemError, e.Component, e.FailedOperation, e.Err)
	}

	if e.Code == Unauthorized {
		return fmt.Sprintf("%s: %v", e.Code, e.Err)
	}

	if e.IncorrectValue != "" {
		return fmt.Sprintf("%s[%s]: %v", e.Code, e.IncorrectValue, e.Err)
	}

	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *CustomError) Unwrap() error {
	return e.Err
}

func (e *CustomError) HTTPCodeMsg() (int, interface{}) {
	var code int

	switch e.Code { //nolint:exhaustive
	case SystemError:
		return http.StatusInternalServerError, map[string]interface{}{
			"code":      SystemError.Name(),
			"component": e.Component,
			"operation": e.FailedOperation,
			"message":   e.Err.Error(),
		}

	case Unauthorized:
		return http.StatusUnauthorized, map[string]interface{}{
			"code":    Unauthorized.Name(),
			"message": e.Err.Error(),
		}

	case ProfileNotFound:
		return http.StatusNotFound, map[string]interface{}{
			"code":    ProfileNotFound.Name(),
			"message": e.Err.Error(),
		}

	case OIDCError:
		return http.StatusBadRequest, map[string]interface{}{
			"error": e.Component,
			"_raw":  e.Err.Error(),
		}

	case AlreadyExist:
		code = http.StatusConflict

	case DoesntExist:
		code = http.StatusNotFound

	case ConditionNotMet:
		code = http.StatusPreconditionFailed

	case InvalidValue:
		fallthrough

	default:
		code = http.StatusBadRequest
	}

	return code, map[string]interface{}{
		"code":           e.Code.Name(),
		"incorrectValue": e.IncorrectValue,
		"message":        e.Err.Error(),
	}
}

// RegistrationError is used to indicate a validation error during dynamic client registration.
// When a registration error condition occurs, the authorization server returns an HTTP 400 status code with content
// type "application/json" consisting of a JSON object describing the error in the response body.
type RegistrationError struct {
	Code string
	Err  error
}

func (e *RegistrationError) Error() string {
	return e.Err.Error()
}

// GetErrorDetails extracts the error message, error code and component from the given error. If the error
// is not a CustomError implementation then the error code and component will be empty.
func GetErrorDetails(err error) (string, string, Component) {
	var ce *CustomError
	if ok := errors.As(err, &ce); ok {
		return ce.Err.Error(), string(ce.Code), ce.Component
	}

	return err.Error(), "", ""
}
