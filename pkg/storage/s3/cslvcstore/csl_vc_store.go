/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslvcstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	contentType           = "application/json"
	amazonPublicDomainFmt = "https://%s.s3.%s.amazonaws.com"

	issuer           = "/issuer"
	issuerProfiles   = issuer + "/groups"
	credentialStatus = "/credentials/status"
)

type s3Uploader interface {
	PutObject(ctx context.Context, input *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, input *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// underlyingCSLWrapperStore is used for storing credentialstatus.CSLVCWrapper
// in a different place then public S3 bucket.
type underlyingCSLWrapperStore interface {
	Get(ctx context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error)
	Upsert(ctx context.Context, cslURL string, cslWrapper *credentialstatus.CSLVCWrapper) error
}

// Store manages profile in mongodb.
type Store struct {
	s3Uploader       s3Uploader
	cslLWrapperStore underlyingCSLWrapperStore
	bucket           string
	region           string
	hostName         string
}

// NewStore creates S3 Store.
func NewStore(
	s3Uploader s3Uploader,
	cslLWrapperStore underlyingCSLWrapperStore,
	bucket, region, hostName string) *Store {
	return &Store{
		s3Uploader:       s3Uploader,
		cslLWrapperStore: cslLWrapperStore,
		bucket:           bucket,
		region:           region,
		hostName:         hostName,
	}
}

// Upsert does upsert operation of credentialstatus.CSLVCWrapper.
func (p *Store) Upsert(ctx context.Context, cslURL string, cslWrapper *credentialstatus.CSLVCWrapper) error {
	// Put CSL.
	_, err := p.s3Uploader.PutObject(ctx, &s3.PutObjectInput{
		Body:        bytes.NewReader(unQuote(cslWrapper.VCByte)),
		Key:         aws.String(p.resolveCSLS3Key(cslURL)),
		Bucket:      aws.String(p.bucket),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("failed to upload CSL: %w", err)
	}

	// Put cslWrapper.
	cslWrapper.VCByte = nil

	if err = p.cslLWrapperStore.Upsert(ctx, cslURL, cslWrapper); err != nil {
		return fmt.Errorf("failed to store cslWrapper: %w", err)
	}

	return nil
}

// Get returns credentialstatus.CSLVCWrapper based on credentialstatus.CSL URL.
func (p *Store) Get(ctx context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error) {
	// Get CSL.
	cslRes, err := p.s3Uploader.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(p.resolveCSLS3Key(cslURL)),
	})
	if err != nil {
		var awsError *types.NoSuchKey
		if errors.As(err, &awsError) {
			return nil, credentialstatus.ErrDataNotFound
		}

		if strings.Contains(err.Error(), "AccessDenied") {
			return nil, credentialstatus.ErrDataNotFound
		}

		return nil, fmt.Errorf("failed to get CSL from S3: %w", err)
	}

	cslBytes, err := io.ReadAll(cslRes.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read CSL body: %w", err)
	}

	// Get CSLWrapper.
	cslWrapper, err := p.cslLWrapperStore.Get(ctx, cslURL)
	if err != nil {
		if errors.Is(err, credentialstatus.ErrDataNotFound) {
			// this is old data (VC doesn't have matching wrapper)
			// so we couldn't get version - return as version 1
			return &credentialstatus.CSLVCWrapper{
				VCByte:  cslBytes,
				Version: 1,
			}, nil
		}

		return nil, fmt.Errorf("failed to get CSL Wrapper from underlying store: %w", err)
	}

	cslWrapper.VCByte = cslBytes

	return cslWrapper, nil
}

// GetCSLURL returns the public URL of credentialstatus.CSL.
func (p *Store) GetCSLURL(_, groupID string, listID credentialstatus.ListID) (string, error) {
	return url.JoinPath(
		p.getAmazonPublicDomain(),
		issuerProfiles,
		groupID,
		credentialStatus,
		string(listID),
	)
}

func (p *Store) resolveCSLS3Key(cslURL string) string {
	return strings.TrimPrefix(cslURL, p.getAmazonPublicDomain())
}

func (p *Store) getAmazonPublicDomain() string {
	if p.hostName != "" {
		return fmt.Sprintf("https://%s", p.hostName)
	}

	return fmt.Sprintf(amazonPublicDomainFmt, p.bucket, p.region)
}

func unQuote(s []byte) []byte {
	if len(s) <= 1 {
		return s
	}

	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}

	return s
}
