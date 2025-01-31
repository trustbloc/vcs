package arieskmsstore_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/storage/awsecret/arieskmsstore"
)

func TestPut(t *testing.T) {
	cl := NewMockClient(gomock.NewController(t))

	prefix := "someprefix/dev1/"

	store := arieskmsstore.NewStore(
		cl,
		prefix,
	)

	cl.EXPECT().CreateSecret(gomock.Any(), gomock.Any()).
		DoAndReturn(func(
			_ context.Context,
			input *secretsmanager.CreateSecretInput,
			_ ...func(*secretsmanager.Options),
		) (*secretsmanager.CreateSecretOutput, error) {
			assert.EqualValues(t, prefix+"someId", *input.Name)

			var parsed arieskmsstore.DataWrapper
			if err := json.Unmarshal(input.SecretBinary, &parsed); err != nil {
				return nil, err
			}

			assert.EqualValues(t, []byte{0x1, 0x2}, parsed.Bin)

			return &secretsmanager.CreateSecretOutput{}, nil
		})

	assert.NoError(t, store.Put("someId", []byte{0x1, 0x2}))
}

func TestGet(t *testing.T) {
	cl := NewMockClient(gomock.NewController(t))

	prefix := "someprefix/dev1"

	store := arieskmsstore.NewStore(
		cl,
		prefix,
	)

	cl.EXPECT().GetSecretValue(gomock.Any(), gomock.Any()).
		DoAndReturn(func(
			_ context.Context,
			input *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options),
		) (*secretsmanager.GetSecretValueOutput, error) {
			assert.EqualValues(t, "someprefix/dev1/someId", *input.SecretId)

			b, err := json.Marshal(arieskmsstore.DataWrapper{
				Bin: []byte{0x1, 0x2},
			})
			assert.NoError(t, err)

			return &secretsmanager.GetSecretValueOutput{
				SecretBinary: b,
			}, nil
		})

	resp, err := store.Get("someId")
	assert.NoError(t, err)

	assert.EqualValues(t, []byte{0x1, 0x2}, resp)
}

func TestDelete(t *testing.T) {
	cl := NewMockClient(gomock.NewController(t))

	prefix := "someprefix/dev1"

	store := arieskmsstore.NewStore(
		cl,
		prefix,
	)

	cl.EXPECT().DeleteSecret(gomock.Any(), gomock.Any()).
		DoAndReturn(func(
			_ context.Context,
			input *secretsmanager.DeleteSecretInput,
			_ ...func(*secretsmanager.Options),
		) (*secretsmanager.DeleteSecretOutput, error) {
			assert.EqualValues(t, "someprefix/dev1/someId", *input.SecretId)

			return &secretsmanager.DeleteSecretOutput{}, nil
		})

	assert.NoError(t, store.Delete("someId"))
}
