package oidc4ci_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestComposer(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := oidc4ci.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
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
					IDTemplate:         "hardcoded:{{.TxID}}:suffix",
					OverrideIssuer:     true,
					OverrideSubjectDID: true,
				},
			},
			&oidc4ci.PrepareCredentialRequest{
				DID: "some-awesome-did",
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, resp)

		assert.EqualValues(t, "hardcoded:some-awesome-id:suffix", resp.Contents().ID)
		assert.EqualValues(t, "did:example:123", resp.Contents().Issuer.ID)
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
