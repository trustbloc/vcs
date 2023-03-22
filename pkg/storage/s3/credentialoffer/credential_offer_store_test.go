/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialoffer_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/s3/credentialoffer"
)

func TestNewStore(t *testing.T) {
	req := &oidc4ci.CredentialOfferResponse{
		CredentialIssuer: "https://localhost",
	}

	t.Run("success", func(t *testing.T) {
		up := NewMockS3Uploader(gomock.NewController(t))
		s := credentialoffer.NewStore(up, "a", "b", "")

		key := ""
		up.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				input *s3.PutObjectInput,
				opts ...func(*s3.Options),
			) (*s3.PutObjectOutput, error) {
				key = *input.Key
				b, err := io.ReadAll(input.Body)
				assert.NoError(t, err)
				var local oidc4ci.CredentialOfferResponse
				assert.NoError(t, json.Unmarshal(b, &local))

				assert.Equal(t, *req, local)
				assert.Equal(t, "a", *input.Bucket)
				assert.NotEmpty(t, *input.Key)
				assert.Equal(t, "application/json", *input.ContentType)

				return &s3.PutObjectOutput{}, nil
			})

		finalURL, err := s.Create(context.TODO(), req)
		assert.NoError(t, err)
		assert.Contains(t, finalURL, fmt.Sprintf("https://a.s3.b.amazonaws.com/%v", key))
		assert.True(t, strings.HasSuffix(key, ".jwt"))
	})

	t.Run("err upload", func(t *testing.T) {
		up := NewMockS3Uploader(gomock.NewController(t))
		s := credentialoffer.NewStore(up, "a", "b", "")

		up.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				input *s3.PutObjectInput,
				opts ...func(*s3.Options),
			) (*s3.PutObjectOutput, error) {
				return nil, errors.New("upload err")
			})

		finalURL, err := s.Create(context.TODO(), req)
		assert.ErrorContains(t, err, "upload err")
		assert.Empty(t, finalURL)
	})
}
