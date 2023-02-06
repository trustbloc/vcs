/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination request_object_store_mocks_test.go -package requestobjectstore_test -source=request_object_store.go -mock_names s3Uploader=MockS3Uploader

package requestobjectstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/pkg/service/requestobject"
)

const (
	contentType = "application/json"
)

var logger = log.New("s3_request_object_store")

type s3Uploader interface {
	PutObjectWithContext(
		ctx aws.Context,
		input *s3.PutObjectInput,
		opts ...request.Option,
	) (*s3.PutObjectOutput, error)

	GetObjectWithContext(
		ctx aws.Context,
		input *s3.GetObjectInput,
		opts ...request.Option,
	) (*s3.GetObjectOutput, error)

	DeleteObjectWithContext(
		ctx aws.Context,
		input *s3.DeleteObjectInput,
		opts ...request.Option,
	) (*s3.DeleteObjectOutput, error)
}

// Store manages profile in mongodb.
type Store struct {
	s3Client s3Uploader
	bucket   string
	region   string
	hostName string
}

// NewStore creates Store.
func NewStore(
	s3Uploader s3Uploader,
	bucket string,
	region string,
	hostName string,
) *Store {
	return &Store{
		s3Client: s3Uploader,
		bucket:   bucket,
		region:   region,
		hostName: hostName,
	}
}

func (p *Store) Create(
	ctx context.Context,
	request requestobject.RequestObject,
) (*requestobject.RequestObject, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	request.ID = uuid.NewString()

	_, err = p.s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Body:        bytes.NewReader(data),
		Key:         aws.String(request.ID),
		Bucket:      aws.String(p.bucket),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		logger.Error(fmt.Sprintf("error uploading to s3 bucket [%v] %+v",
			p.bucket, err))
		logger.Error(spew.Sdump(err))

		return nil, err
	}

	return &request, nil
}

// Find profile by give id.
func (p *Store) Find(
	ctx context.Context,
	id string,
) (*requestobject.RequestObject, error) {
	res, err := p.s3Client.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(id),
	})
	if err != nil {
		return nil, err
	}

	var targetObject requestobject.RequestObject
	if err = json.NewDecoder(res.Body).Decode(&targetObject); err != nil {
		return nil, err
	}

	return &targetObject, nil
}

func (p *Store) Delete(
	ctx context.Context,
	id string,
) error {
	_, err := p.s3Client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(id),
	})
	return err
}

func (p *Store) GetResourceURL(key string) string {
	hostName := fmt.Sprintf("https://%s.s3.%s.amazonaws.com", p.bucket, p.region)

	if p.hostName != "" {
		hostName = fmt.Sprintf("https://%s", p.hostName)
	}

	return fmt.Sprintf("%s/%s", hostName, key)
}
