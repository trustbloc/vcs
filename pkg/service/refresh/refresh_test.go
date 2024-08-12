package refresh_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/refresh"
)

func TestCreateRefreshState(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		dataProtect := NewMockdataProtector(gomock.NewController(t))
		srv := refresh.NewRefreshService(&refresh.Config{
			DataProtector: dataProtect,
		})

		claims := map[string]interface{}{
			"a": "b",
		}

		dataProtect.EXPECT().Encrypt(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, bytes []byte) (*dataprotect.EncryptedData, error) {
				b, err := json.Marshal(claims) // nolint
				assert.NoError(t, err)

				assert.EqualValues(t, b, bytes)

				return &dataprotect.EncryptedData{
					Encrypted: b,
				}, nil
			})

		resp, err := srv.CreateRefreshState(context.TODO(), &refresh.CreateRefreshStateRequest{
			CredentialID:          "some_cred_id",
			Issuer:                profileapi.Issuer{},
			Claims:                claims,
			CredentialName:        nil,
			CredentialDescription: nil,
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, resp)
	})
}
