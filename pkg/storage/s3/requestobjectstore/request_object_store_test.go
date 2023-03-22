/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requestobjectstore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
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

	t.Run("success", func(t *testing.T) {
		uploader := NewMockS3Uploader(gomock.NewController(t))
		uploader.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				input *s3.PutObjectInput,
				opts ...func(*s3.Options),
			) (*s3.PutObjectOutput, error) {
				assert.Equal(t, "application/json", *input.ContentType)
				assert.NotEmpty(t, *input.Key)
				assert.Equal(t, "awesome-bucket", *input.Bucket)

				data, err2 := io.ReadAll(input.Body)
				assert.NoError(t, err2)
				assert.Equal(t, []byte(targetObj.Content), data)

				return &s3.PutObjectOutput{}, nil
			})

		repo := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west", "")

		result, err := repo.Create(context.TODO(), *targetObj)
		assert.NoError(t, err)
		assert.NotEmpty(t, result.ID)
	})

	t.Run("fail", func(t *testing.T) {
		uploader := NewMockS3Uploader(gomock.NewController(t))
		uploader.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("s3 error"))

		repo := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west", "")

		result, err := repo.Create(context.TODO(), *targetObj)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "s3 error")
	})
}

func TestFind(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		uploader := NewMockS3Uploader(gomock.NewController(t))
		uploader.EXPECT().GetObject(gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				input *s3.GetObjectInput,
				opts ...func(*s3.Options),
			) (*s3.GetObjectOutput, error) {
				assert.Equal(t, "awesome-bucket", *input.Bucket)
				assert.Equal(t, "1234", *input.Key)
				return &s3.GetObjectOutput{
					Body: io.NopCloser(bytes.NewBufferString(`value`)),
				}, nil
			})

		repo := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west", "")
		resp, err := repo.Find(context.TODO(), "1234")

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "value", resp.Content)
	})

	t.Run("error", func(t *testing.T) {
		uploader := NewMockS3Uploader(gomock.NewController(t))
		uploader.EXPECT().GetObject(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("unexpected s3 error"))

		repo := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west", "")
		resp, err := repo.Find(context.TODO(), "1234")
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "unexpected s3 error")
	})
}

func TestDelete(t *testing.T) {
	uploader := NewMockS3Uploader(gomock.NewController(t))
	uploader.EXPECT().DeleteObject(gomock.Any(), gomock.Any()).
		DoAndReturn(func(
			ctx context.Context,
			input *s3.DeleteObjectInput,
			opts ...func(*s3.Options),
		) (*s3.DeleteObjectOutput, error) {
			assert.Equal(t, "awesome-bucket", *input.Bucket)
			assert.Equal(t, "1234", *input.Key)

			return &s3.DeleteObjectOutput{}, nil
		})

	resp := requestobjectstore.NewStore(uploader, "awesome-bucket", "us-west", "")
	assert.NoError(t, resp.Delete(context.TODO(), "1234"))
}

func TestBuildUrl(t *testing.T) {
	resp := requestobjectstore.NewStore(nil, "awesome-bucket", "us-west", "")
	assert.Equal(t, "https://awesome-bucket.s3.us-west.amazonaws.com/1111", resp.GetResourceURL("1111"))
}
