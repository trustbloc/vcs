package refresh_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/refresh"
)

func TestCreateRefreshState(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		dataProtect := NewMockdataProtector(gomock.NewController(t))
		store := NewMockclaimDataStore(gomock.NewController(t))
		txStore := NewMocktransactionStore1(gomock.NewController(t))

		srv := refresh.NewRefreshService(&refresh.Config{
			DataProtector: dataProtect,
			ClaimsStore:   store,
			TxStore:       txStore,
		})

		claims := map[string]interface{}{
			"a": "b",
		}
		claimsJSON, err := json.Marshal(claims) // nolint
		assert.NoError(t, err)

		dataProtect.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, bytes []byte) (*dataprotect.EncryptedData, error) {
				assert.EqualValues(t, claimsJSON, bytes)

				return &dataprotect.EncryptedData{
					Encrypted: claimsJSON,
				}, nil
			})

		store.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, i int32, data *issuecredential.ClaimData) (string, error) {
				assert.EqualValues(t, data.EncryptedData.Encrypted, claimsJSON)
				return "some_claims_id", nil
			})

		issuer := profileapi.Issuer{
			ID:             "some_issuer",
			Version:        "2.0",
			OrganizationID: "org1",
			WebHook:        "webhook",
		}

		txStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				_ int32,
				data *issuecredential.TransactionData,
			) (*issuecredential.Transaction, error) {
				assert.EqualValues(t, issuer.ID, data.ProfileID)
				assert.EqualValues(t, issuer.Version, data.ProfileVersion)
				assert.True(t, data.IsPreAuthFlow)
				assert.EqualValues(t, issuer.OrganizationID, data.OrgID)
				assert.EqualValues(t, "some_issuer-some_cred_id", data.OpState)
				assert.EqualValues(t, issuer.WebHook, data.WebHookURL)

				assert.Len(t, data.CredentialConfiguration, 1)
				assert.EqualValues(t, issuecredential.ClaimDataTypeClaims,
					data.CredentialConfiguration[0].ClaimDataType)
				assert.EqualValues(t, "some_claims_id", data.CredentialConfiguration[0].ClaimDataID)

				return &issuecredential.Transaction{
					ID: "some_tx_id",
				}, nil
			})

		resp, err := srv.CreateRefreshState(context.TODO(), &refresh.CreateRefreshStateRequest{
			CredentialID:          "some_cred_id",
			Issuer:                issuer,
			Claims:                claims,
			CredentialName:        nil,
			CredentialDescription: nil,
		})

		assert.NoError(t, err)
		assert.EqualValues(t, "some_tx_id", resp)
	})
}

func TestRequestRefreshState(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		txStore := NewMocktransactionStore1(gomock.NewController(t))

		srv := refresh.NewRefreshService(&refresh.Config{
			TxStore:   txStore,
			VcsAPIURL: "https://localhost/api",
		})

		txStore.EXPECT().FindByOpState(gomock.Any(), "some_issuer-some_cred_id").
			Return(&issuecredential.Transaction{}, nil)

		resp, err := srv.RequestRefreshStatus(context.TODO(), "some_cred_id", profileapi.Issuer{
			ID: "some_issuer",
		})
		assert.NoError(t, err)

		assert.EqualValues(t, "VerifiableCredentialRefreshService2021", resp.RefreshServiceType.Type)
		assert.EqualValues(t, "We need to see your existing credentials",
			resp.VerifiablePresentationRequest.Query.Name)

		assert.Len(t, resp.VerifiablePresentationRequest.Query.InputDescriptors, 1)
		assert.Len(t, resp.VerifiablePresentationRequest.Query.InputDescriptors[0].Constraints.Fields, 1)

		field := resp.VerifiablePresentationRequest.Query.InputDescriptors[0].Constraints.Fields[0]

		assert.EqualValues(t, []string{
			"$.id",
		}, field.Path)

		assert.EqualValues(t, "string", *field.Filter.Type)
		assert.EqualValues(t, "some_cred_id", field.Filter.Const)

		assert.EqualValues(t, "https://localhost/api", resp.Domain)
		assert.NotEmpty(t, resp.Challenge)
	})

	t.Run("no state", func(t *testing.T) {
		txStore := NewMocktransactionStore1(gomock.NewController(t))

		srv := refresh.NewRefreshService(&refresh.Config{
			TxStore: txStore,
		})

		txStore.EXPECT().FindByOpState(gomock.Any(), "some_issuer-some_cred_id").
			Return(nil, nil)

		resp, err := srv.RequestRefreshStatus(context.TODO(), "some_cred_id", profileapi.Issuer{
			ID: "some_issuer",
		})
		assert.NoError(t, err)
		assert.Nil(t, resp)
	})
}
