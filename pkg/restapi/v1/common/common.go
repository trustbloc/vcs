/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate oapi-codegen --config=openapi.cfg.yaml ../../../../docs/v1/common.yaml

package common

import (
	"fmt"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

func ValidateVCFormat(format VCFormat) (vcsverifiable.Format, error) {
	switch format {
	case JwtVcJson:
		return vcsverifiable.Jwt, nil
	case JwtVcJsonLd:
		return vcsverifiable.Jwt, nil
	case LdpVc:
		return vcsverifiable.Ldp, nil
	case CwtVcLd:
		return vcsverifiable.Cwt, nil
	}

	return "", fmt.Errorf("unsupported vc format %s, use one of next [%s, %s]", format, JwtVcJsonLd, LdpVc)
}
func ValidateVPFormat(format VPFormat) (vcsverifiable.Format, error) {
	switch format {
	case JwtVp:
		return vcsverifiable.Jwt, nil
	case LdpVp:
		return vcsverifiable.Ldp, nil
	case CwtVp:
		return vcsverifiable.Cwt, nil
	}

	return "", fmt.Errorf("unsupported vp format %s, use one of next [%s, %s]", format, JwtVcJsonLd, LdpVc)
}

func MapToVCFormat(format vcsverifiable.Format) (vcsverifiable.OIDCFormat, error) {
	switch format {
	case vcsverifiable.Jwt:
		return vcsverifiable.JwtVCJson, nil
	case vcsverifiable.Ldp:
		return vcsverifiable.JwtVCJsonLD, nil
	case vcsverifiable.Cwt:
		return vcsverifiable.CwtVcLD, nil
	}

	return "", fmt.Errorf("vc format missmatch %s, rest api supports only [%s, %s]", format, JwtVcJsonLd, LdpVc)
}

func MapToVPFormat(format vcsverifiable.Format) (VPFormat, error) {
	switch format {
	case vcsverifiable.Jwt:
		return JwtVp, nil
	case vcsverifiable.Ldp:
		return LdpVp, nil
	case vcsverifiable.Cwt:
		return CwtVp, nil
	}

	return "", fmt.Errorf("vc format missmatch %s, rest api supports only [%s, %s]", format, JwtVcJsonLd, LdpVc)
}

func ValidateDIDMethod(method DIDMethod) (profileapi.Method, error) {
	switch method {
	case DIDMethodKey:
		return profileapi.KeyDIDMethod, nil
	case DIDMethodWeb:
		return profileapi.WebDIDMethod, nil
	case DIDMethodOrb:
		return profileapi.OrbDIDMethod, nil
	}

	return "", fmt.Errorf("unsupported did method %s, use one of next [%s, %s, %s]",
		method, DIDMethodKey, DIDMethodWeb, DIDMethodOrb)
}

func MapToDIDMethod(method profileapi.Method) (DIDMethod, error) {
	switch method {
	case profileapi.KeyDIDMethod:
		return DIDMethodKey, nil
	case profileapi.WebDIDMethod:
		return DIDMethodWeb, nil
	case profileapi.OrbDIDMethod:
		return DIDMethodOrb, nil
	}

	return "",
		fmt.Errorf("did method missmatch %s, rest api supports only [%s, %s, %s]",
			method, DIDMethodKey, DIDMethodWeb, DIDMethodOrb)
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
