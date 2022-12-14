/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requestobjectstore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
	"github.com/trustbloc/vcs/pkg/storage/s3/requestobjectstore"
)

func TestCreate(t *testing.T) {
	targetObj := &requestobject.RequestObject{
		Content:                  "any string",
		AccessRequestObjectEvent: &spi.Event{ID: "1234"},
	}
	b, err := json.Marshal(targetObj)
	assert.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		uploader := NewMockS3Uploader(gomock.NewController(t))
		uploader.EXPECT().PutObjectWithContext(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx aws.Context,
				input *s3.PutObjectInput,
				opts ...request.Option,
			) (*s3.PutObjectOutput, error) {
				assert.Equal(t, "application/json", *input.ContentType)
				assert.NotEmpty(t, *input.Key)
				assert.Equal(t, "awesome-bucket", *input.Bucket)

				data, err2 := io.ReadAll(input.Body)
				assert.NoError(t, err2)
				assert.Equal(t, b, data)

				return &s3.PutObjectOutput{}, nil
			})

		repo := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west")

		result, err := repo.Create(context.TODO(), *targetObj)
		assert.NoError(t, err)
		assert.NotEmpty(t, result.ID)
	})

	t.Run("fail", func(t *testing.T) {
		uploader := NewMockS3Uploader(gomock.NewController(t))
		uploader.EXPECT().PutObjectWithContext(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("s3 error"))

		repo := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west")

		result, err := repo.Create(context.TODO(), *targetObj)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "s3 error")
	})
}

func TestFind(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		uploader := NewMockS3Uploader(gomock.NewController(t))
		uploader.EXPECT().GetObjectWithContext(gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx aws.Context,
				input *s3.GetObjectInput,
				opts ...request.Option,
			) (*s3.GetObjectOutput, error) {
				assert.Equal(t, "awesome-bucket", *input.Bucket)
				assert.Equal(t, "1234", *input.Key)
				return &s3.GetObjectOutput{
					Body: io.NopCloser(bytes.NewBufferString(`{"id" : "5678", "content" : "111"}`)),
				}, nil
			})

		repo := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west")
		resp, err := repo.Find(context.TODO(), "1234")

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "5678", resp.ID)
		assert.Equal(t, "111", resp.Content)
	})

	t.Run("invalid json", func(t *testing.T) {
		uploader := NewMockS3Uploader(gomock.NewController(t))
		uploader.EXPECT().GetObjectWithContext(gomock.Any(), gomock.Any()).
			Return(&s3.GetObjectOutput{
				Body: io.NopCloser(bytes.NewBufferString("{")),
			}, nil)

		repo := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west")
		resp, err := repo.Find(context.TODO(), "1234")
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "unexpected EOF")
	})

	t.Run("error", func(t *testing.T) {
		uploader := NewMockS3Uploader(gomock.NewController(t))
		uploader.EXPECT().GetObjectWithContext(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("unexpected s3 error"))

		repo := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west")
		resp, err := repo.Find(context.TODO(), "1234")
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "unexpected s3 error")
	})
}

func TestDelete(t *testing.T) {
	uploader := NewMockS3Uploader(gomock.NewController(t))
	uploader.EXPECT().DeleteObjectWithContext(gomock.Any(), gomock.Any()).
		DoAndReturn(func(
			ctx aws.Context,
			input *s3.DeleteObjectInput,
			opts ...request.Option,
		) (*s3.DeleteObjectOutput, error) {
			assert.Equal(t, "awesome-bucket", *input.Bucket)
			assert.Equal(t, "1234", *input.Key)

			return &s3.DeleteObjectOutput{}, nil
		})

	resp := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west")
	assert.NoError(t, resp.Delete(context.TODO(), "1234"))
}

func TestBuildUrl(t *testing.T) {
	resp := requestobjectstore.NewStore(nil, "awesome-bucket", "us-west")
	assert.Equal(t, "https://awesome-bucket.s3.us-west.amazonaws.com/1111", resp.GetResourceURL("1111"))
}
