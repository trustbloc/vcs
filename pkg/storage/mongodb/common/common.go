/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/kms"
)

type KMSConfigDocument struct {
	KMSType           kms.Type `bson:"type"`
	Endpoint          string   `bson:"endpoint"`
	SecretLockKeyPath string   `bson:"secretLockKeyPath"`
	DBType            string   `bson:"dbType"`
	DBURL             string   `bson:"dbURL"`
	DBPrefix          string   `bson:"dbPrefix"`
}

type SigningDIDDocument struct {
	DID            string `bson:"did"`
	Creator        string `bson:"creator"`
	UpdateKeyURL   string `bson:"updateKeyURL"`
	RecoveryKeyURL string `bson:"recoveryKeyURL"`
}

func SigningDIDToDocument(signingDID *did.SigningDID) *SigningDIDDocument {
	if signingDID == nil {
		return nil
	}

	return &SigningDIDDocument{
		DID:            signingDID.DID,
		Creator:        signingDID.Creator,
		UpdateKeyURL:   signingDID.UpdateKeyURL,
		RecoveryKeyURL: signingDID.RecoveryKeyURL,
	}
}

func SigningDIDFromDocument(signingDID *SigningDIDDocument) *did.SigningDID {
	if signingDID == nil {
		return nil
	}

	return &did.SigningDID{
		DID:            signingDID.DID,
		Creator:        signingDID.Creator,
		UpdateKeyURL:   signingDID.UpdateKeyURL,
		RecoveryKeyURL: signingDID.RecoveryKeyURL,
	}
}

func KMSConfigToDocument(kmsConfig *kms.Config) *KMSConfigDocument {
	if kmsConfig == nil {
		return nil
	}

	return &KMSConfigDocument{
		KMSType:           kmsConfig.KMSType,
		Endpoint:          kmsConfig.Endpoint,
		SecretLockKeyPath: kmsConfig.SecretLockKeyPath,
		DBType:            kmsConfig.DBType,
		DBURL:             kmsConfig.DBURL,
		DBPrefix:          kmsConfig.DBPrefix,
	}
}

func KMSConfigFromDocument(kmsConfig *KMSConfigDocument) *kms.Config {
	if kmsConfig == nil {
		return nil
	}

	return &kms.Config{
		KMSType:           kmsConfig.KMSType,
		Endpoint:          kmsConfig.Endpoint,
		SecretLockKeyPath: kmsConfig.SecretLockKeyPath,
		DBType:            kmsConfig.DBType,
		DBURL:             kmsConfig.DBURL,
		DBPrefix:          kmsConfig.DBPrefix,
	}
}
