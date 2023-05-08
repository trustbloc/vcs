/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"errors"
	"fmt"
	"time"

	docjsonld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

const (
	// https://www.w3.org/TR/vc-data-model/#base-context
	baseContext = "https://www.w3.org/2018/credentials/v1"
)

var logger = log.New("vc-validate-credentials")

func ValidateCredential(
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

	if checkExpiration && credential.Expired != nil && time.Now().UTC().After(credential.Expired.Time) {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential",
			errors.New("credential expired"))
	}

	// Due to the current implementation in AFGO (func verifiable.ParseCredential()),
	// strict credential validation can only be applied to LDP or unsecured JWT.
	// Means, that in case first argument in verifiable.ParseCredential() is a JWS -
	// variable externalJWT will not be empty and validation will be skipped.
	// So to apply strict validation against JWT/JWS - needs to remove
	// credential.JWT field, then convert to bytes and explicitly call validation func.
	if enforceStrictValidation && isJWT(cred) {
		// If it's SDJWT
		if credential.SDJWTHashAlg != "" {
			return validateSDJWTCredential(credential, documentLoader)
		}

		jwtRepresentation := credential.JWT
		credential.JWT = ""

		err = validateCredentialClaims(credential, documentLoader)
		if err != nil {
			return nil, fmt.Errorf("failed to validate JWT credential claims: %w", err)
		}

		credential.JWT = jwtRepresentation
	}

	return credential, nil
}

func validateSDJWTCredential(
	credential *verifiable.Credential, documentLoader jsonld.DocumentLoader) (*verifiable.Credential, error) {
	displayCredential, err := credential.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
	if err != nil {
		return nil, fmt.Errorf("failed to create display credential: %w", err)
	}

	v, _ := displayCredential.MarshalJSON()

	logger.Info("display credential for sd jwt", log.WithID(string(v)))

	err = validateCredentialClaims(displayCredential, documentLoader)
	if err != nil {
		return nil, fmt.Errorf("failed to validate SDJWT credential claims: %w", err)
	}

	return credential, nil
}

func validateCredentialClaims(credential *verifiable.Credential, documentLoader jsonld.DocumentLoader) error {
	credentialBytes, err := credential.MarshalJSON()
	if err != nil {
		return fmt.Errorf("unable to marshal credential: %w", err)
	}

	err = docjsonld.ValidateJSONLD(string(credentialBytes),
		docjsonld.WithDocumentLoader(documentLoader),
		docjsonld.WithStrictValidation(true),
		docjsonld.WithStrictContextURIPosition(baseContext))
	if err != nil {
		return fmt.Errorf("crdential validation failed: %w", err)
	}

	return nil
}

func isJWT(cred interface{}) bool {
	str, isStr := cred.(string)

	return isStr && (jwt.IsJWTUnsecured(str) || jwt.IsJWS(str))
}
