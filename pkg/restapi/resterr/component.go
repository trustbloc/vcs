/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

type Component string

//nolint:gosec
const (
	IssuerSvcComponent                  Component = "issuer.service"
	IssuerProfileSvcComponent           Component = "issuer.profile-service"
	IssuerCredentialRefreshSvcComponent Component = "issuer.credential-refresh-service"
	IssueCredentialSvcComponent         Component = "issuer.issue-credential-service"
	IssuerOIDC4ciSvcComponent           Component = "issuer.oidc4ci-service"

	VerifierVerifyCredentialSvcComponent  Component = "verifier.verify-credential-service"
	VerifierOIDC4vpSvcComponent           Component = "verifier.oidc4vp-service"
	VerifierProfileSvcComponent           Component = "verifier.profile-service"
	VerifierTxnMgrComponent               Component = "verifier.txn-mgr"
	VerifierVCSignerComponent             Component = "verifier.vc-signer"
	VerifierKMSRegistryComponent          Component = "verifier.kms-registry"
	VerifierPresentationVerifierComponent Component = "verifier.presentation-verifier"
	VerifierDataIntegrityVerifier         Component = "verifier.data-integrity-verifier"

	ClientManagerComponent                 Component = "client-manager"
	WellKnownSvcComponent                  Component = "well-known-service"
	DataProtectorComponent                 Component = "data-protector"
	ClaimDataStoreComponent                Component = "claim-data-store"
	TransactionStoreComponent              Component = "transaction-store"
	CryptoJWTSignerComponent               Component = "crypto-jwt-signer"
	CredentialOfferReferenceStoreComponent Component = "credential-offer-reference-store"
	RedisComponent                         Component = "redis-service"
)
