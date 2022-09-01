/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// CreateCredentialRequest input data for issuer rest api.
type CreateCredentialRequest struct {
	Context []string           `json:"@context,omitempty"`
	Subject verifiable.Subject `json:"credentialSubject"`
	Issuer  verifiable.Issuer  `json:"issuer"`
	Type    []string           `json:"type,omitempty"`
	Profile string             `json:"profile,omitempty"`
}

// UpdateCredentialStatusRequest request struct for updating vc status.
type UpdateCredentialStatusRequest struct {
	CredentialID     string           `json:"credentialId"`
	CredentialStatus CredentialStatus `json:"credentialStatus"`
}

// CredentialStatus credential status.
type CredentialStatus struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

// StoreVCRequest stores the credential with profile name.
type StoreVCRequest struct {
	// profile id
	Profile string `json:"profile"`
	// credential
	Credential string `json:"credential"`
}

// ProfileRequest issuer profile request params.
type ProfileRequest struct {
	// profile id - avoid using special characters or whitespaces
	// required: true
	Name string `json:"name"`
	// uri of the issuer
	// required: true
	URI string `json:"uri"`
	// signature type - suppored Ed25519Signature2018, JSONWebSignature2020, BbsBlsSignature2020
	// required: true
	SignatureType string `json:"signatureType"`
	// type of key to create inside default DID Document by the system - Ed25519 or P256
	// required: true
	DIDKeyType string `json:"didKeyType"`
	// signature representation
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation"`
	// DID to be imported - if empty, the issuer will create a new DID
	DID string `json:"did"`
	// private key associated with DID to be imported
	DIDPrivateKey string `json:"didPrivateKey"`
	// DID key id to be used for signing
	DIDKeyID string `json:"didKeyID"`
	// config to disable VC status in during credential issuance
	DisableVCStatus bool `json:"disableVCStatus"`
	// overwrite issuer id in VC - if true, then override the issuer id with profile DID
	OverwriteIssuer bool `json:"overwriteIssuer,omitempty"`
}

// IssueCredentialRequest request for issuing credential.
type IssueCredentialRequest struct {
	Credential json.RawMessage         `json:"credential,omitempty"`
	Opts       *IssueCredentialOptions `json:"options,omitempty"`
}

// IssueCredentialOptions options for issuing credential.
type IssueCredentialOptions struct {
	// VerificationMethod is the URI of the verificationMethod used for the proof.
	// If omitted first ed25519 public key of DID (Issuer or Profile DID) will be used.
	VerificationMethod string `json:"verificationMethod,omitempty"`
	// AssertionMethod is verification method to be used for credential proof.
	// When provided along with 'VerificationMethod' property, 'VerificationMethod' takes precedence.
	// deprecated : to be removed in future, 'VerificationMethod' field will be used to pass verification method.
	AssertionMethod string `json:"assertionMethod,omitempty"`
	// ProofPurpose is purpose of the proof. If omitted "assertionMethod" will be used.
	ProofPurpose string `json:"proofPurpose,omitempty"`
	// Created date of the proof. If omitted system time will be used.
	Created *time.Time `json:"created,omitempty"`
	// Challenge is added to the proof
	Challenge string `json:"challenge,omitempty"`
	// Domain is added to the proof
	Domain string `json:"domain,omitempty"`
	// The method of credential status to issue the credential including. If omitted credential status will be included.
	CredentialStatus CredentialStatusOpt `json:"credentialStatus,omitempty"`
}

// CredentialStatusOpt credential status option.
type CredentialStatusOpt struct {
	Type string `json:"type"`
}

// ComposeCredentialRequest for composing and issuing credential.
type ComposeCredentialRequest struct {
	Issuer                  string          `json:"issuer,omitempty"`
	Subject                 string          `json:"subject,omitempty"`
	Types                   []string        `json:"types,omitempty"`
	IssuanceDate            *time.Time      `json:"issuanceDate,omitempty"`
	ExpirationDate          *time.Time      `json:"expirationDate,omitempty"`
	Claims                  json.RawMessage `json:"claims,omitempty"`
	Evidence                json.RawMessage `json:"evidence,omitempty"`
	TermsOfUse              json.RawMessage `json:"termsOfUse,omitempty"`
	CredentialFormat        string          `json:"credentialFormat,omitempty"`
	ProofFormat             string          `json:"proofFormat,omitempty"`
	CredentialFormatOptions json.RawMessage `json:"credentialFormatOptions,omitempty"`
	ProofFormatOptions      json.RawMessage `json:"proofFormatOptions,omitempty"`
}

// GenerateKeyPairRequest generating key pair request.
type GenerateKeyPairRequest struct {
	// nolint: lll
	// key type - refer for https://github.com/hyperledger/aries-framework-go/blob/badfb20d82bec3e0154d49f2cf6072b8fcd72a21/pkg/kms/api.go#L80-L123 supported options.
	KeyType kms.KeyType `json:"keyType,omitempty"`
}

// GenerateKeyPairResponse contains response from KMS generate keypair API.
type GenerateKeyPairResponse struct {
	PublicKey string `json:"publicKey,omitempty"`
	KeyID     string `json:"keyID,omitempty"`
}
