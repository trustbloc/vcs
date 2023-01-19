package crypto

import (
	"crypto"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
)

func TestCrypto_getSDJWTCredentialSubjectDigests(t *testing.T) {
	testSubject := verifiable.Subject{
		ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
		CustomFields: map[string]interface{}{
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
			"name":   "Jayden Doe",
			"degree": map[string]interface{}{
				"type":   "BachelorDegree",
				"degree": "MIT",
			},
		},
	}
	testVc := verifiable.Credential{
		ID:      "http://example.edu/credentials/1872",
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		Subject: testSubject,
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Issuer: verifiable.Issuer{
			ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
		},
		CustomFields: map[string]interface{}{
			"first_name": "First name",
			"last_name":  "Last name",
			"info":       "Info",
		},
	}

	c := &Crypto{}

	t.Run("OK", func(t *testing.T) {
		credential := testVc
		got, err := c.getSDJWTCredentialSubjectDigests(&credential, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, got)

		t.Run("Check Subject", func(t *testing.T) {
			subject, ok := got.Subject.(verifiable.Subject)
			require.True(t, ok)
			require.Equal(t, testSubject.ID, subject.ID)
			require.Len(t, subject.CustomFields, 2)
			sd, ok := subject.CustomFields[common.SDKey]
			require.True(t, ok)
			digests, ok := sd.([]string)
			require.True(t, ok)
			require.Len(t, digests, 3)
			sdAlg, ok := subject.CustomFields[common.SDAlgorithmKey]
			require.True(t, ok)
			require.Equal(t, sdAlg.(string), "sha-256")
			require.Len(t, got.Disclosures, 3)
		})

		t.Run("Check Disclosures and digests", func(t *testing.T) {
			subject, ok := got.Subject.(verifiable.Subject)
			require.True(t, ok)

			digests, ok := subject.CustomFields[common.SDKey].([]string)
			require.True(t, ok)

			for _, disclosure := range got.Disclosures {
				hash, err := common.GetHash(crypto.SHA256, disclosure)
				require.NoError(t, err)
				require.True(t, hashExist(t, hash, digests))
			}

			disclosuresClaims, err := common.GetDisclosureClaims(got.Disclosures)
			require.NoError(t, err)

			for _, disclosureClaim := range disclosuresClaims {
				value, ok := credential.Subject.(verifiable.Subject).CustomFields[disclosureClaim.Name]
				require.True(t, ok)
				require.Equal(t, value, disclosureClaim.Value)
			}
		})
	})

	t.Run("OK subject as a string", func(t *testing.T) {
		credential := testVc

		credential.Subject = "did:example:ebfeb1f712ebc6f1c276e12ec21"
		got, err := c.getSDJWTCredentialSubjectDigests(&credential, crypto.SHA256)
		require.NoError(t, err)
		require.Equal(t, credential.Subject, got.Subject)
		require.Empty(t, got.Disclosures)
	})

	t.Run("Error create JWT claims from credential", func(t *testing.T) {
		credential := testVc

		credential.Subject = nil
		got, err := c.getSDJWTCredentialSubjectDigests(&credential, crypto.SHA256)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to create JWT claims")
		require.Empty(t, got)
	})

	t.Run("Error create SD-JWT token from credential - unsupported hash alg", func(t *testing.T) {
		credential := testVc
		got, err := c.getSDJWTCredentialSubjectDigests(&credential, crypto.Hash(21))
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to create SD-JWT token")
		require.Empty(t, got)
	})
}

func hashExist(t *testing.T, hash string, digests []string) bool {
	t.Helper()

	for _, d := range digests {
		if d == hash {
			return true
		}
	}

	return false
}
