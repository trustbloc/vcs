package oidc4ci_test

import (
	"context"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	util "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestComposer(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := oidc4ci.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			Types: []string{"VerifiableCredential"},
			Context: []string{
				"https://www.w3.org/2018/credentials/v1",
			},
			Subject: []verifiable.Subject{{ID: "xxx:yyy"}},
		}, verifiable.CustomFields{})
		assert.NoError(t, err)

		expectedExpiration := time.Now().UTC()

		resp, err := srv.Compose(
			context.TODO(),
			cred,
			&oidc4ci.Transaction{
				ID: "some-awesome-id",
				TransactionData: oidc4ci.TransactionData{
					DID: "did:example:123",
				},
			},
			&oidc4ci.TxCredentialConfiguration{
				CredentialComposeConfiguration: &oidc4ci.CredentialComposeConfiguration{
					IDTemplate:         "hardcoded:{{.TxID}}:suffix",
					OverrideIssuer:     true,
					OverrideSubjectDID: true,
				},
				CredentialExpiresAt: &expectedExpiration,
			},
			&oidc4ci.PrepareCredentialRequest{
				DID: "some-awesome-did",
			},
		)

		assert.NotNil(t, resp.Contents().Issued)
		assert.NotNil(t, resp.Contents().Expired)

		assert.NoError(t, err)
		assert.NotNil(t, resp)

		credJSON, err := resp.MarshalAsJSONLD()
		assert.NoError(t, err)

		parsedCred, err := verifiable.ParseCredential(credJSON,
			verifiable.WithCredDisableValidation(),
			verifiable.WithDisabledProofCheck(),
		)
		assert.NoError(t, err)

		assert.EqualValues(t, "hardcoded:some-awesome-id:suffix", resp.Contents().ID)
		assert.EqualValues(t, "did:example:123", resp.Contents().Issuer.ID)
		assert.EqualValues(t, "some-awesome-did", resp.Contents().Subject[0].ID)
		assert.EqualValues(t, expectedExpiration, parsedCred.Contents().Expired.Time)
		assert.NotNil(t, expectedExpiration, parsedCred.Contents().Issued)
	})

	t.Run("success with prev-id", func(t *testing.T) {
		srv := oidc4ci.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			ID:      "some-id",
			Expired: util.NewTime(time.Now()),
			Issuer: &verifiable.Issuer{
				ID: "did:example:123",
				CustomFields: map[string]interface{}{
					"key":  "value",
					"name": "issuer",
				},
			},
			Subject: []verifiable.Subject{{ID: "xxx:yyy"}},
		}, verifiable.CustomFields{})
		assert.NoError(t, err)

		resp, err := srv.Compose(
			context.TODO(),
			cred,
			&oidc4ci.Transaction{
				ID: "some-awesome-id",
				TransactionData: oidc4ci.TransactionData{
					DID: "did:example:123",
				},
			},
			&oidc4ci.TxCredentialConfiguration{
				CredentialComposeConfiguration: &oidc4ci.CredentialComposeConfiguration{
					IDTemplate:         "{{.CredentialID}}:suffix",
					OverrideIssuer:     true,
					OverrideSubjectDID: true,
				},
				CredentialExpiresAt: lo.ToPtr(time.Now()),
			},
			&oidc4ci.PrepareCredentialRequest{
				DID: "some-awesome-did",
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, resp)

		assert.EqualValues(t, "some-id:suffix", resp.Contents().ID)
		assert.EqualValues(t, "did:example:123", resp.Contents().Issuer.ID)
		assert.EqualValues(t, "value", resp.Contents().Issuer.CustomFields["key"])
		assert.EqualValues(t, "issuer", resp.Contents().Issuer.CustomFields["name"])

		assert.EqualValues(t, "some-awesome-did", resp.Contents().Subject[0].ID)
	})

	t.Run("invalid template", func(t *testing.T) {
		srv := oidc4ci.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{}, verifiable.CustomFields{})
		assert.NoError(t, err)

		resp, err := srv.Compose(
			context.TODO(),
			cred,
			&oidc4ci.Transaction{
				ID: "some-awesome-id",
				TransactionData: oidc4ci.TransactionData{
					DID: "did:example:123",
				},
			},
			&oidc4ci.TxCredentialConfiguration{
				CredentialComposeConfiguration: &oidc4ci.CredentialComposeConfiguration{
					IDTemplate:     "hardcoded:{{.NotExistingValue.$x}}:suffix",
					OverrideIssuer: true,
				},
			},
			&oidc4ci.PrepareCredentialRequest{},
		)

		assert.ErrorContains(t, err, "bad character")
		assert.Nil(t, resp)
	})

	t.Run("missing compose", func(t *testing.T) {
		srv := oidc4ci.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{}, verifiable.CustomFields{})
		assert.NoError(t, err)

		resp, err := srv.Compose(context.TODO(), cred, nil, nil, nil)
		assert.Equal(t, cred, resp)
		assert.NoError(t, err)
	})
}
