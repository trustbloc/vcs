/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/common.yaml

package common

import (
	"fmt"

	"github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

const (
	kmsConfigType              = "kmsConfig.type"
	kmsConfigSecretLockKeyPath = "kmsConfig.secretLockKeyPath" //nolint: gosec
	kmsConfigEndpoint          = "kmsConfig.endpoint"
	kmsConfigDBURL             = "kmsConfig.dbURL"
	kmsConfigDBType            = "kmsConfig.dbType"
	kmsConfigDBPrefix          = "kmsConfig.dbPrefix"
)

func ValidateVCFormat(format VCFormat) (vc.Format, error) {
	switch format {
	case JwtVc:
		return vc.Jwt, nil
	case LdpVc:
		return vc.Ldp, nil
	}

	return "", fmt.Errorf("unsupported vc format %s, use one of next [%s, %s]", format, JwtVc, LdpVc)
}

func MapToVCFormat(format vc.Format) (VCFormat, error) {
	switch format {
	case vc.Jwt:
		return JwtVc, nil
	case vc.Ldp:
		return LdpVc, nil
	}

	return "", fmt.Errorf("vc format missmatch %s, rest api supports only [%s, %s]", format, JwtVc, LdpVc)
}

func ValidateVPFormat(format VPFormat) (vc.Format, error) {
	switch format {
	case JwtVp:
		return vc.Jwt, nil
	case LdpVp:
		return vc.Ldp, nil
	}

	return "", fmt.Errorf("unsupported vc format %s, use one of next [%s, %s]", format, JwtVc, LdpVc)
}

func MapToVPFormat(format vc.Format) (VPFormat, error) {
	switch format {
	case vc.Jwt:
		return JwtVp, nil
	case vc.Ldp:
		return LdpVp, nil
	}

	return "", fmt.Errorf("vc format missmatch %s, rest api supports only [%s, %s]", format, JwtVc, LdpVc)
}

func ValidateDIDMethod(method DIDMethod) (did.Method, error) {
	switch method {
	case DIDMethodKey:
		return did.KeyDIDMethod, nil
	case DIDMethodWeb:
		return did.WebDIDMethod, nil
	case DIDMethodOrb:
		return did.OrbDIDMethod, nil
	}

	return "", fmt.Errorf("unsupported did method %s, use one of next [%s, %s, %s]",
		method, DIDMethodKey, DIDMethodWeb, DIDMethodOrb)
}

func MapToDIDMethod(method did.Method) (DIDMethod, error) {
	switch method {
	case did.KeyDIDMethod:
		return DIDMethodKey, nil
	case did.WebDIDMethod:
		return DIDMethodWeb, nil
	case did.OrbDIDMethod:
		return DIDMethodOrb, nil
	}

	return "",
		fmt.Errorf("did method missmatch %s, rest api supports only [%s, %s, %s]",
			method, DIDMethodKey, DIDMethodWeb, DIDMethodOrb)
}

func ValidateKMSConfig(config *KMSConfig) (*kms.Config, error) {
	if config == nil {
		return nil, nil //nolint: nilnil
	}

	kmsType, err := ValidateKMSType(config.Type)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigType, err)
	}

	if kmsType == kms.AWS || kmsType == kms.Web {
		if config.Endpoint == nil {
			return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigEndpoint,
				fmt.Errorf("enpoint is required for %s kms", config.Type))
		}
		return &kms.Config{
			KMSType:  kmsType,
			Endpoint: *config.Endpoint,
		}, nil
	}

	if config.SecretLockKeyPath == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigSecretLockKeyPath,
			fmt.Errorf("secretLockKeyPath is required for %s kms", config.Type))
	}

	if config.DbType == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigDBType,
			fmt.Errorf("dbType is required for %s kms", config.Type))
	}

	if config.DbURL == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigDBURL,
			fmt.Errorf("dbURL is required for %s kms", config.Type))
	}

	if config.DbPrefix == nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, kmsConfigDBPrefix,
			fmt.Errorf("dbPrefix is required for %s kms", config.Type))
	}

	return &kms.Config{
		KMSType:           kmsType,
		SecretLockKeyPath: *config.SecretLockKeyPath,
		DBType:            *config.DbType,
		DBURL:             *config.DbURL,
		DBPrefix:          *config.DbPrefix,
	}, nil
}

func ValidateKMSType(kmsType KMSConfigType) (kms.Type, error) {
	switch kmsType {
	case KMSConfigTypeAws:
		return kms.AWS, nil
	case KMSConfigTypeLocal:
		return kms.Local, nil
	case KMSConfigTypeWeb:
		return kms.Web, nil
	}

	return "", fmt.Errorf("unsupported kms type %s, use one of next [%s, %s, %s]",
		kmsType, KMSConfigTypeAws, KMSConfigTypeLocal, KMSConfigTypeWeb)
}

func MapToKMSConfigType(kmsType kms.Type) (KMSConfigType, error) {
	switch kmsType {
	case kms.AWS:
		return KMSConfigTypeAws, nil
	case kms.Local:
		return KMSConfigTypeLocal, nil
	case kms.Web:
		return KMSConfigTypeWeb, nil
	}

	return "",
		fmt.Errorf("kms type missmatch %s, rest api supportes only [%s, %s, %s]",
			kmsType, KMSConfigTypeAws, KMSConfigTypeLocal, KMSConfigTypeWeb)
}
