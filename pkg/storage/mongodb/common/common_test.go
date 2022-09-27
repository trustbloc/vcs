/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/kms"
)

func TestKMSConfigFromToDocument(t *testing.T) {
	expected := &kms.Config{
		KMSType:           "test1",
		Endpoint:          "test2",
		SecretLockKeyPath: "test3",
		DBType:            "test4",
		DBURL:             "test5",
		DBPrefix:          "test6",
	}

	result := KMSConfigFromDocument(KMSConfigToDocument(expected))

	if diff := deep.Equal(expected, result); diff != nil {
		t.Error(diff)
	}

	require.Nil(t, KMSConfigFromDocument(KMSConfigToDocument(nil)))
}

func TestSigningDIDFromDocument(t *testing.T) {
	expected := &did.SigningDID{}

	result := SigningDIDFromDocument(SigningDIDToDocument(expected))

	if diff := deep.Equal(expected, result); diff != nil {
		t.Error(diff)
	}

	require.Nil(t, SigningDIDFromDocument(SigningDIDToDocument(nil)))
}
