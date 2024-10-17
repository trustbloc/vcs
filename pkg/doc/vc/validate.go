/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"context"
	"errors"
	"fmt"
	"time"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

func ValidateCredential(
	_ context.Context,
	cred interface{},
	formats []vcsverifiable.Format,
	checkExpiration bool,
	enforceStrictValidation bool,
	documentLoader jsonld.DocumentLoader,
	opts ...verifiable.CredentialOpt,
) (*verifiable.Credential, error) {
	vcBytes, err := vcsverifiable.ValidateFormat(cred, formats)
	if err != nil {
		return nil, err
	}

	// validate the VC (ignore the proof and issuanceDate)
	credential, err := verifiable.ParseCredential(vcBytes, opts...)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	credentialContents := credential.Contents()

	if checkExpiration && credentialContents.Expired != nil && time.Now().UTC().After(credentialContents.Expired.Time) {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential",
			errors.New("credential expired"))
	}

	// Due to the current implementation in AFGO (func verifiable.ParseCredential()),
	// strict credential validation can only be applied to LDP or unsecured JWT.
	// Means, that in case first argument in verifiable.ParseCredential() is a JWS -
	// variable externalJWT will not be empty and validation will be skipped.
	if enforceStrictValidation {
		// If it's SDJWT
		if credentialContents.SDJWTHashAlg != nil {
			return validateSDJWTCredential(credential, documentLoader)
		}

		// TODO: should it be only json ld validation as was originally, or also schema validation.
		// By default for json-ld we will have both.
		err = credential.ValidateCredential(
			verifiable.WithJSONLDDocumentLoader(documentLoader),
			verifiable.WithStrictValidation(),
			verifiable.WithJSONLDValidation(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to validate JWT credential claims: %w", err)
		}
	}

	return credential, nil
}

func validateSDJWTCredential(
	credential *verifiable.Credential,
	documentLoader jsonld.DocumentLoader,
) (*verifiable.Credential, error) {
	displayCredential, err := credential.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
	if err != nil {
		return nil, fmt.Errorf("failed to create display credential: %w", err)
	}

	err = displayCredential.ValidateCredential(
		verifiable.WithJSONLDDocumentLoader(documentLoader),
		verifiable.WithStrictValidation(),
		verifiable.WithJSONLDValidation())
	if err != nil {
		return nil, fmt.Errorf("failed to validate SDJWT credential claims: %w", err)
	}

	return credential, nil
}

func isJWT(cred interface{}) bool {
	str, isStr := cred.(string)

	return isStr && (jwt.IsJWTUnsecured(str) || jwt.IsJWS(str))
}
