/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslstore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	contentType           = "application/json"
	amazonPublicDomainFmt = "https://%s.s3.%s.amazonaws.com"

	issuer           = "/issuer"
	issuerProfiles   = issuer + "/profiles"
	credentialStatus = "/credentials/status"
)

type s3Uploader interface {
	PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error)
	GetObject(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
}

// underlyingCSLWrapperStore is used for storing
// credentialstatus.CSLWrapper and credentialstatus.ListID in a different place then public S3 bucket.
type underlyingCSLWrapperStore interface {
	Get(cslURL string) (*credentialstatus.CSLWrapper, error)
	Upsert(cslWrapper *credentialstatus.CSLWrapper) error
	GetLatestListID() (credentialstatus.ListID, error)
	UpdateLatestListID() error
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
	s3Uploader s3Uploader, cslLWrapperStore underlyingCSLWrapperStore, bucket, region, hostName string) *Store {
	return &Store{
		s3Uploader:       s3Uploader,
		cslLWrapperStore: cslLWrapperStore,
		bucket:           bucket,
		region:           region,
		hostName:         hostName,
	}
}

// Upsert does upsert operation of credentialstatus.CSLWrapper.
func (p *Store) Upsert(cslWrapper *credentialstatus.CSLWrapper) error {
	// Put CSL.
	_, err := p.s3Uploader.PutObject(&s3.PutObjectInput{
		Body:        bytes.NewReader(unQuote(cslWrapper.VCByte)),
		Key:         aws.String(p.resolveCSLS3Key(cslWrapper.VC.ID)),
		Bucket:      aws.String(p.bucket),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("failed to upload CSL: %w", err)
	}

	// Put cslWrapper.
	cslWrapper.VCByte = nil

	if err = p.cslLWrapperStore.Upsert(cslWrapper); err != nil {
		return fmt.Errorf("failed to store cslWrapper: %w", err)
	}

	return nil
}

// Get returns credentialstatus.CSLWrapper based on credentialstatus.CSL URL.
func (p *Store) Get(cslURL string) (*credentialstatus.CSLWrapper, error) {
	// Get CSL.
	cslRes, err := p.s3Uploader.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(p.resolveCSLS3Key(cslURL)),
	})
	if err != nil {
		var awsError awserr.Error
		if ok := errors.As(err, &awsError); ok && awsError.Code() == s3.ErrCodeNoSuchKey {
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
	cslWrapper, err := p.cslLWrapperStore.Get(cslURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get CSLWrapper from underlying store: %w", err)
	}

	cslWrapper.VCByte = cslBytes

	return cslWrapper, nil
}

func (p *Store) GetLatestListID() (credentialstatus.ListID, error) {
	return p.cslLWrapperStore.GetLatestListID()
}

func (p *Store) UpdateLatestListID() error {
	return p.cslLWrapperStore.UpdateLatestListID()
}

// GetCSLURL returns the public URL of credentialstatus.CSL.
func (p *Store) GetCSLURL(_, groupID string, listID credentialstatus.ListID) (string, error) {
	return url.JoinPath(
		p.getAmazonPublicDomain(),
		issuerProfiles,
		groupID,
		credentialStatus,
		fmt.Sprintf("%s.json", listID),
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
