package issuecredential_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

//go:embed testdata/university_degree.jsonld
var exampleCredential string

func TestPrepareCredential(t *testing.T) {
	t.Run("success from claims", func(t *testing.T) {
		srv := issuecredential.NewPrepareCredentialService(&issuecredential.PrepareCredentialServiceConfig{})

		cred, err := srv.PrepareCredential(context.TODO(), &issuecredential.PrepareCredentialsRequest{
			TxID:       "",
			ClaimData:  map[string]interface{}{},
			IssuerDID:  "",
			SubjectDID: "",
			CredentialConfiguration: &issuecredential.TxCredentialConfiguration{
				ClaimDataType:         issuecredential.ClaimDataTypeClaims,
				CredentialTemplate:    &profileapi.CredentialTemplate{},
				CredentialDescription: "some description",
				CredentialName:        "some name",
				CredentialExpiresAt:   lo.ToPtr(time.Now()),
			},
			IssuerID:      "",
			IssuerVersion: "",
		})

		assert.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("success from vc", func(t *testing.T) {
		compose := NewMockcomposer(gomock.NewController(t))

		srv := issuecredential.NewPrepareCredentialService(&issuecredential.PrepareCredentialServiceConfig{
			Composer: compose,
		})

		var parsedCred map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(exampleCredential), &parsedCred))

		req := &issuecredential.PrepareCredentialsRequest{
			TxID:       "",
			ClaimData:  parsedCred,
			IssuerDID:  "",
			SubjectDID: "",
			CredentialConfiguration: &issuecredential.TxCredentialConfiguration{
				ClaimDataType:         issuecredential.ClaimDataTypeVC,
				CredentialTemplate:    &profileapi.CredentialTemplate{},
				CredentialDescription: "some description",
				CredentialName:        "some name",
				CredentialExpiresAt:   lo.ToPtr(time.Now()),
			},
			IssuerID:      "",
			IssuerVersion: "",
		}

		result := &verifiable.Credential{}
		compose.EXPECT().Compose(gomock.Any(), gomock.Any(), req).
			Return(result, nil)

		cred, err := srv.PrepareCredential(context.TODO(), req)

		assert.NoError(t, err)
		assert.NotNil(t, cred)
	})

	t.Run("err from vc", func(t *testing.T) {
		compose := NewMockcomposer(gomock.NewController(t))

		srv := issuecredential.NewPrepareCredentialService(&issuecredential.PrepareCredentialServiceConfig{
			Composer: compose,
		})

		var parsedCred map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(exampleCredential), &parsedCred))

		req := &issuecredential.PrepareCredentialsRequest{
			TxID:       "",
			ClaimData:  parsedCred,
			IssuerDID:  "",
			SubjectDID: "",
			CredentialConfiguration: &issuecredential.TxCredentialConfiguration{
				ClaimDataType:         issuecredential.ClaimDataTypeVC,
				CredentialTemplate:    &profileapi.CredentialTemplate{},
				CredentialDescription: "some description",
				CredentialName:        "some name",
				CredentialExpiresAt:   lo.ToPtr(time.Now()),
			},
			IssuerID:      "",
			IssuerVersion: "",
		}

		compose.EXPECT().Compose(gomock.Any(), gomock.Any(), req).
			Return(nil, errors.New("some err"))

		cred, err := srv.PrepareCredential(context.TODO(), req)

		assert.ErrorContains(t, err, "some err")
		assert.Nil(t, cred)
	})
}
