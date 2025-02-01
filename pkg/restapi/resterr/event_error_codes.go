package resterr

type EventErrorCode = string

//nolint:gosec
const (
	SystemError                      EventErrorCode = "system-error"
	InvalidValue                     EventErrorCode = "invalid-value"
	InvalidCredentialConfigurationID EventErrorCode = "invalid-credential-configuration-id"
	CredentialTypeNotSupported       EventErrorCode = "credential-type-not-supported"
	CredentialFormatNotSupported     EventErrorCode = "credential-format-not-supported"
	InvalidStateTransition           EventErrorCode = "invalid-state-transition"
)
