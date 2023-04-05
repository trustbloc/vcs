/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cslvcstore

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	bucket   = "test-bucket"
	region   = "test-region"
	hostName = ""
)

var (
	//go:embed testdata/university_degree.jsonld
	sampleVCJsonLD string
	//go:embed testdata/university_degree.jwt
	sampleVCJWT string
)

type mockS3Uploader struct {
	t      *testing.T
	m      map[string]*s3.PutObjectInput
	putErr error
	getErr error
}

func (m *mockS3Uploader) PutObject(
	ctx context.Context, input *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	assert.Equal(m.t, "application/json", *input.ContentType)
	assert.NotEmpty(m.t, *input.Key)
	assert.Equal(m.t, bucket, *input.Bucket)
	assert.False(m.t, strings.HasPrefix(*input.Key,
		NewStore(
			nil,
			bucket,
			region,
			hostName).getAmazonPublicDomain()))
	m.m[*input.Key] = input

	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Uploader) GetObject(
	ctx context.Context, input *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	assert.NotEmpty(m.t, *input.Key)
	assert.Equal(m.t, bucket, *input.Bucket)
	assert.False(m.t, strings.HasPrefix(*input.Key,
		NewStore(
			nil,
			bucket,
			region,
			hostName).getAmazonPublicDomain()))

	putData, ok := m.m[*input.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}

	b, err := io.ReadAll(putData.Body)
	assert.NoError(m.t, err)

	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func TestWrapperStore(t *testing.T) {
	tests := []struct {
		name string
		file []byte
	}{
		{
			name: "JSON-LD",
			file: []byte(sampleVCJsonLD),
		},
		{
			name: "JWT",
			file: []byte(sampleVCJWT),
		},
	}
	for _, tt := range tests {
		t.Run("Create, update, find wrapper VC "+tt.name, func(t *testing.T) {
			client := &mockS3Uploader{m: map[string]*s3.PutObjectInput{}, t: t}
			store := NewStore(client, bucket, region, hostName)
			ctx := context.Background()

			vc, err := verifiable.ParseCredential(tt.file,
				verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
				verifiable.WithDisabledProofCheck())
			assert.NoError(t, err)

			vcBytes, err := vc.MarshalJSON()
			assert.NoError(t, err)

			wrapperCreated := &credentialstatus.CSLVCWrapper{
				VCByte: vcBytes,
				VC:     vc,
			}

			// Create - Find
			err = store.Upsert(ctx, vc.ID, wrapperCreated)
			assert.NoError(t, err)

			var wrapperFound *credentialstatus.CSLVCWrapper
			wrapperFound, err = store.Get(ctx, vc.ID)
			assert.NoError(t, err)
			compareWrappers(t, wrapperCreated, wrapperFound)

			// Update - Find
			wrapperUpdated := &credentialstatus.CSLVCWrapper{
				VCByte: vcBytes,
			}

			err = store.Upsert(ctx, vc.ID, wrapperUpdated)
			assert.NoError(t, err)

			wrapperFound, err = store.Get(ctx, vc.ID)
			assert.NoError(t, err)

			compareWrappers(t, wrapperUpdated, wrapperFound)
		})
	}

	t.Run("Unexpected error from s3 client on upsert CSL", func(t *testing.T) {
		errClient := &mockS3Uploader{m: map[string]*s3.PutObjectInput{}, t: t, putErr: errors.New("some error")}
		wrapperCreated := &credentialstatus.CSLVCWrapper{
			VC: &verifiable.Credential{ID: ""},
		}
		err := NewStore(errClient, bucket, region, hostName).
			Upsert(context.Background(), "", wrapperCreated)

		assert.Error(t, err)
		assert.ErrorContains(t, err, "failed to upload CSL")
	})

	t.Run("Find non-existing CSL", func(t *testing.T) {
		errClient := &mockS3Uploader{
			m: map[string]*s3.PutObjectInput{},
			t: t,
		}

		resp, err := NewStore(errClient, bucket, region, hostName).
			Get(context.Background(), "http://example.gov/credentials/3732")

		assert.Nil(t, resp)
		assert.ErrorIs(t, err, credentialstatus.ErrDataNotFound)
	})

	t.Run("Find non-existing cslWrapper", func(t *testing.T) {
		errClient := &mockS3Uploader{
			m: map[string]*s3.PutObjectInput{
				"http://example.gov/credentials/3732": {Body: bytes.NewReader([]byte(``))},
			},
			t: t,
		}

		resp, err := NewStore(errClient, bucket, region, hostName).
			Get(context.Background(), "http://example.gov/credentials/3732")

		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("Unexpected error from s3 client on get", func(t *testing.T) {
		errClient := &mockS3Uploader{m: map[string]*s3.PutObjectInput{}, t: t, getErr: errors.New("some error")}

		resp, err := NewStore(errClient, bucket, region, hostName).
			Get(context.Background(), "63451f2358bde34a13b5d95b")

		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "failed to get CSL from S3")
	})
}

func TestStore_GetCSLURL(t *testing.T) {
	store := NewStore(nil, bucket, region, hostName)
	require.NotNil(t, store)

	cslURL, err := store.GetCSLURL(
		"https://example.com", "test_issuer", "1")
	assert.NoError(t, err)
	assert.Equal(t,
		"https://test-bucket.s3.test-region.amazonaws.com/issuer/groups/test_issuer/credentials/status/1",
		cslURL)

	// Convert to CSL S3 key.
	cslS3Key := store.resolveCSLS3Key(cslURL)
	assert.Equal(t,
		"issuer/groups/test_issuer/credentials/status/1",
		cslS3Key)
}

func compareWrappers(t *testing.T, wrapperExpected, wrapperFound *credentialstatus.CSLVCWrapper) {
	t.Helper()

	vcExpected, err := verifiable.ParseCredential(wrapperExpected.VCByte,
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		verifiable.WithDisabledProofCheck())
	assert.NoError(t, err)

	vcFound, err := verifiable.ParseCredential(wrapperFound.VCByte,
		verifiable.WithJSONLDDocumentLoader(testutil.DocumentLoader(t)),
		verifiable.WithDisabledProofCheck())
	assert.NoError(t, err)

	if !assert.Equal(t, vcExpected, vcFound) {
		t.Errorf("VC got = %v, want %v",
			vcFound, vcExpected)
	}
}

func Test_unQuote(t *testing.T) {
	type args struct {
		s []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "OK",
			args: args{
				s: []byte(`"abc"`),
			},
			want: []byte(`abc`),
		},
		{
			name: "OK one quote",
			args: args{
				s: []byte(`abc"`),
			},
			want: []byte(`abc"`),
		},
		{
			name: "OK no quotes",
			args: args{
				s: []byte(`abc`),
			},
			want: []byte(`abc`),
		},
		{
			name: "OK empty string",
			args: args{
				s: []byte(``),
			},
			want: []byte(``),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, unQuote(tt.args.s), "unQuote(%v)", tt.args.s)
		})
	}
}
