/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	latestListIDEntryKey  = "latestListID.json"
	contentType           = "application/json"
	amazonPublicDomainFmt = "https://%s.s3.%s.amazonaws.com"

	issuer           = "/issuer"
	latestListIDPath = issuer + "/latestlistid"
	issuerProfiles   = issuer + "/profiles"
	credentialStatus = "/credentials/status"
)

type s3Uploader interface {
	PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error)
	GetObject(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
}

// Store manages profile in mongodb.
type Store struct {
	s3Uploader s3Uploader
	bucket     string
	region     string
	hostName   string
}

type latestListID struct {
	ListID int `json:"listId"`
}

// NewStore creates Store.
func NewStore(s3Uploader s3Uploader, bucket, region, hostName string) *Store {
	return &Store{
		s3Uploader: s3Uploader,
		bucket:     bucket,
		region:     region,
		hostName:   hostName,
	}
}

// Upsert does upsert operation of cslWrapper against underlying MongoDB.
func (p *Store) Upsert(cslWrapper *credentialstatus.CSLWrapper) error {
	data, err := json.Marshal(cslWrapper)
	if err != nil {
		return fmt.Errorf("failed to marshal cslWrapper: %w", err)
	}

	_, err = p.s3Uploader.PutObject(&s3.PutObjectInput{
		Body:        bytes.NewReader(data),
		Key:         aws.String(p.resolveCSLS3Key(cslWrapper.VC.ID)),
		Bucket:      aws.String(p.bucket),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("failed to upload cslWrapper: %w", err)
	}

	return nil
}

// Get returns credentialstatus.CSLWrapper.
func (p *Store) Get(id string) (*credentialstatus.CSLWrapper, error) {
	res, err := p.s3Uploader.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(p.resolveCSLS3Key(id)),
	})
	if err != nil {
		var awsError awserr.Error
		if ok := errors.As(err, &awsError); ok && awsError.Code() == s3.ErrCodeNoSuchKey {
			return nil, credentialstatus.ErrDataNotFound
		}

		return nil, fmt.Errorf("failed to get CSLWrapper from S3: %w", err)
	}

	var cslWrapper credentialstatus.CSLWrapper
	if err = json.NewDecoder(res.Body).Decode(&cslWrapper); err != nil {
		return nil, fmt.Errorf("failed to decode cslWrapper: %w", err)
	}

	return &cslWrapper, nil
}

func (p *Store) UpdateLatestListID(id int) error {
	_, err := p.createListID(id)
	return err
}

func (p *Store) GetLatestListID() (int, error) {
	res, err := p.s3Uploader.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(p.resolveLatestListIDS3Key()),
	})
	if err != nil {
		var awsError awserr.Error
		if ok := errors.As(err, &awsError); ok && awsError.Code() == s3.ErrCodeNoSuchKey {
			return p.createListID(1)
		}

		return -1, fmt.Errorf("failed to get latestListID from S3: %w", err)
	}

	var listID latestListID
	if err = json.NewDecoder(res.Body).Decode(&listID); err != nil {
		return -1, fmt.Errorf("failed to decode latestListID: %w", err)
	}

	return listID.ListID, nil
}

// GetCSLWrapperURL returns the URL of CSLWrapper.
func (p *Store) GetCSLWrapperURL(issuerProfileURL, issuerProfileID, statusID string) (string, error) {
	return url.JoinPath(
		p.getAmazonPublicDomain(),
		issuerProfiles,
		issuerProfileID,
		credentialStatus,
		fmt.Sprintf("%s.json", statusID),
	)
}

func (p *Store) createListID(id int) (int, error) {
	data, err := json.Marshal(latestListID{ListID: id})
	if err != nil {
		return -1, fmt.Errorf("failed to marshal latestListID: %w", err)
	}

	_, err = p.s3Uploader.PutObject(&s3.PutObjectInput{
		Body:        bytes.NewReader(data),
		Key:         aws.String(p.resolveLatestListIDS3Key()),
		Bucket:      aws.String(p.bucket),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return -1, fmt.Errorf("failed to upload latestListID: %w", err)
	}

	return id, nil
}

func (p *Store) resolveCSLS3Key(cslVCID string) string {
	return strings.TrimPrefix(cslVCID, p.getAmazonPublicDomain())
}

func (p *Store) resolveLatestListIDS3Key() string {
	return filepath.Join(latestListIDPath, latestListIDEntryKey)
}

func (p *Store) getAmazonPublicDomain() string {
	if p.hostName != "" {
		return fmt.Sprintf("https://%s", p.hostName)
	}

	return fmt.Sprintf(amazonPublicDomainFmt, p.bucket, p.region)
}
