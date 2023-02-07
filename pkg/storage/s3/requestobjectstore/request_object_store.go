/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination request_object_store_mocks_test.go -package requestobjectstore_test -source=request_object_store.go -mock_names s3Uploader=MockS3Uploader

package requestobjectstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/google/uuid"

	"github.com/trustbloc/vcs/pkg/service/requestobject"
)

const (
	contentType = "application/json"
)

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
	request.ID = uuid.NewString()

	_, err := p.s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Body:        bytes.NewReader([]byte(request.Content)),
		Key:         aws.String(request.ID),
		Bucket:      aws.String(p.bucket),
		ContentType: aws.String(contentType),
	})
	if err != nil {
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

	buf := new(strings.Builder)
	_, err = io.Copy(buf, res.Body)
	if err != nil {
		return nil, err
	}

	return &requestobject.RequestObject{
		Content: buf.String(),
	}, nil
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
