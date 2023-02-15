package credentialoffer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/google/uuid"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

//go:generate mockgen -destination credential_offer_mocks_test.go -package credentialoffer_test -source=credential_offer_store.go -mock_names s3Uploader=MockS3Uploader

type s3Uploader interface {
	PutObjectWithContext(
		ctx aws.Context,
		input *s3.PutObjectInput,
		opts ...request.Option,
	) (*s3.PutObjectOutput, error)
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
	request *oidc4ci.CredentialOfferResponse,
) (string, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("%v.jwt", uuid.NewString())

	_, err = p.s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Body:        bytes.NewReader(data),
		Key:         aws.String(key),
		Bucket:      aws.String(p.bucket),
		ContentType: aws.String("application/json"),
	}, nil)
	if err != nil {
		return "", err
	}

	return p.getResourceURL(key), nil
}

func (p *Store) getResourceURL(key string) string {
	hostName := fmt.Sprintf("https://%s.s3.%s.amazonaws.com", p.bucket, p.region)

	if p.hostName != "" {
		hostName = fmt.Sprintf("https://%s", p.hostName)
	}

	return fmt.Sprintf("%s/%s", hostName, key)
}
