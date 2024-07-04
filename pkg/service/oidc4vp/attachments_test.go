package oidc4vp_test

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

var (
	//go:embed testdata/university_degree_embedded_attachment.jsonld
	sampleVCWithEmbeddedAttachment string

	//go:embed testdata/university_degree_remote_attachment.jsonld
	sampleVCWithRemoteAttachment string

	//go:embed testdata/university_degree_evidence_attachment.jsonld
	sampleVCWithEvidenceAttachment string

	//go:embed testdata/university_degree_with_attachments.jsonld
	sampleVCWitAttachments string
)

func TestAttachment(t *testing.T) {
	t.Run("no attachment in credential", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCJsonLD), &data))

		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, nil)
		assert.NoError(t, err)
		assert.Empty(t, resp)
	})

	t.Run("with embedded attachment", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEmbeddedAttachment), &data))

		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, nil)
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, "base64content", attachment.DataURI)
		assert.Empty(t, attachment.Error)
	})

	t.Run("with remote attachment err", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithRemoteAttachment), &data))

		mockHTTP := NewMockHttpClient(gomock.NewController(t))
		srv := oidc4vp.NewAttachmentService(mockHTTP)

		mockHTTP.EXPECT().Do(gomock.Any()).
			DoAndReturn(func(request *http.Request) (*http.Response, error) {
				assert.EqualValues(t, "https://someurl.local", request.URL.String())
				assert.EqualValues(t, "GET", request.Method)

				return nil, errors.New("connection failed")
			})

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, nil)
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, "https://someurl.local", attachment.DataURI)
		assert.EqualValues(t, "failed to handle remote attachment: failed to fetch url: connection failed",
			attachment.Error)
	})

	t.Run("with remote attachment invalid status", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithRemoteAttachment), &data))

		mockHTTP := NewMockHttpClient(gomock.NewController(t))
		srv := oidc4vp.NewAttachmentService(mockHTTP)

		mockHTTP.EXPECT().Do(gomock.Any()).
			DoAndReturn(func(request *http.Request) (*http.Response, error) {
				assert.EqualValues(t, "https://someurl.local", request.URL.String())
				assert.EqualValues(t, "GET", request.Method)

				return &http.Response{
					Body: io.NopCloser(bytes.NewBuffer([]byte(
						"file not found",
					))),
					StatusCode: http.StatusNotFound,
				}, nil
			})

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, nil)
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, "https://someurl.local", attachment.DataURI)
		assert.EqualValues(t, "failed to handle remote attachment: unexpected status code: 404 and body file not found",
			attachment.Error)
	})

	t.Run("with embedded attachment as string type", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEmbeddedAttachment), &data))

		data["credentialSubject"].(map[string]interface{})["attachment1"].(map[string]interface{})["type"] = "EmbeddedAttachment" //nolint
		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, nil)
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, "base64content", attachment.DataURI)
		assert.Empty(t, attachment.Error)
	})

	t.Run("with embedded attachment as string arr", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEmbeddedAttachment), &data))

		data["credentialSubject"].(map[string]interface{})["attachment1"].(map[string]interface{})["type"] = []string{"EmbeddedAttachment"} //nolint
		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, nil)
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, "base64content", attachment.DataURI)
		assert.Empty(t, attachment.Error)
	})

	t.Run("multiple attachments", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWitAttachments), &data))

		mockHTTP := NewMockHttpClient(gomock.NewController(t))
		srv := oidc4vp.NewAttachmentService(mockHTTP)

		var mut sync.Mutex
		urlsCalled := []string{}

		mockHTTP.EXPECT().Do(gomock.Any()).
			DoAndReturn(func(request *http.Request) (*http.Response, error) {
				mut.Lock()
				urlsCalled = append(urlsCalled, request.URL.String())
				defer mut.Unlock()
				assert.EqualValues(t, "GET", request.Method)

				return &http.Response{
					Body: io.NopCloser(bytes.NewBuffer([]byte(
						fmt.Sprintf("base64content-%s", request.URL.String()),
					))),
					Header: map[string][]string{
						"Content-Type": {"image/svg"},
					},
					StatusCode: http.StatusOK,
				}, nil
			}).Times(2)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, nil)
		assert.NoError(t, err)
		assert.Len(t, resp, 3)

		sort.Strings(urlsCalled)
		assert.EqualValues(t, []string{"https://localhost/cat.png", "https://localhost/photo.png"}, urlsCalled)

		sort.Slice(resp, func(i, j int) bool {
			return resp[i].ID < resp[j].ID
		})

		attachment := resp[1]
		assert.EqualValues(t, "doc12", attachment.ID)
		assert.EqualValues(t, "base64content", attachment.DataURI)
		assert.Empty(t, attachment.Error)

		attachment = resp[0]
		assert.EqualValues(t, "doc1", attachment.ID)
		assert.EqualValues(t, "data:image/svg;base64,YmFzZTY0Y29udGVudC1odHRwczovL2xvY2FsaG9zdC9jYXQucG5n",
			attachment.DataURI)
		assert.Empty(t, attachment.Error)

		assert.Empty(t, attachment.Error)

		attachment = resp[2]
		assert.EqualValues(t, "doc445", attachment.ID)
		assert.EqualValues(t, "data:image/svg;base64,YmFzZTY0Y29udGVudC1odHRwczovL2xvY2FsaG9zdC9waG90by5wbmc=",
			attachment.DataURI)

		assert.Empty(t, attachment.Error)
	})
}

func TestValidateEvidences(t *testing.T) {
	t.Run("no attachments", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCJsonLD), &data))

		srv := oidc4vp.NewAttachmentService(nil)
		att, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, nil)
		assert.NoError(t, err)
		assert.Len(t, att, 0)
	})

	t.Run("empty idToken", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEvidenceAttachment), &data))

		srv := oidc4vp.NewAttachmentService(nil)
		att, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, nil)
		assert.Len(t, att, 1)
		assert.NoError(t, err)

		assert.Contains(t, att[0].Error, "id token attachments are empty")
	})

	t.Run("success", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEvidenceAttachment), &data))

		srv := oidc4vp.NewAttachmentService(nil)
		att, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}}, map[string]string{
			"doc1": "data:application/json;base64,aGVsbG8gd29ybGQh",
		})

		assert.Len(t, att, 1)
		assert.NoError(t, err)
		assert.EqualValues(t, "data:application/json;base64,aGVsbG8gd29ybGQh", att[0].DataURI)
		assert.Empty(t, att[0].Error)
	})

	t.Run("success SHA-384", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEvidenceAttachment), &data))

		att := data["credentialSubject"].(map[string]interface{})["attachment1"].(map[string]interface{}) //nolint
		att["hash"] = "d33d40f7010ce34aa86efd353630309ed5c3d7ffac66d988825cf699f4803ccdf3f033230612f0945332fb580d8af805"
		att["hash-alg"] = "SHA-384"

		srv := oidc4vp.NewAttachmentService(nil)
		attRes, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}},
			map[string]string{
				"doc1": "data:application/json;base64,aGVsbG8gd29ybGQh",
			})

		assert.Len(t, attRes, 1)
		assert.NoError(t, err)
		assert.EqualValues(t, "data:application/json;base64,aGVsbG8gd29ybGQh", attRes[0].DataURI)
		assert.Empty(t, attRes[0].Error)
	})

	t.Run("attachment not found in id token", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEvidenceAttachment), &data))

		srv := oidc4vp.NewAttachmentService(nil)
		att, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}},
			map[string]string{
				"doc2": "data:application/json;base64,aGVsbG8gd29ybGQh",
			})

		assert.NoError(t, err)
		assert.Contains(t, att[0].Error, "id token attachment not found for id: doc1")
	})

	t.Run("invalid base64", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEvidenceAttachment), &data))

		srv := oidc4vp.NewAttachmentService(nil)
		att, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}},
			map[string]string{
				"doc1": "data:application/json;base64,xxx",
			})

		assert.NoError(t, err)
		assert.Contains(t, att[0].Error, "failed to decode base64 body id token attachment")
	})

	t.Run("invalid hash", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEvidenceAttachment), &data))

		srv := oidc4vp.NewAttachmentService(nil)
		att, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}},
			map[string]string{
				"doc1": "data:application/json;base64,eHh4",
			})

		assert.NoError(t, err)
		assert.Contains(t, att[0].Error, "hash: hash mismatch")
	})

	t.Run("invalid hash SHA-384", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEvidenceAttachment), &data))

		att := data["credentialSubject"].(map[string]interface{})["attachment1"].(map[string]interface{}) //nolint
		att["hash-alg"] = "SHA-384"

		srv := oidc4vp.NewAttachmentService(nil)
		attRes, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}},
			map[string]string{
				"doc1": "data:application/json;base64,aGVsbG8gd29ybGQh",
			})

		assert.NoError(t, err)
		assert.Contains(t, attRes[0].Error, "hash: hash mismatch")
	})

	missingFields := []string{"id", "hash", "hash-alg"}
	for _, field := range missingFields {
		t.Run(fmt.Sprintf("missing %s", field), func(t *testing.T) {
			var data map[string]interface{}
			assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEvidenceAttachment), &data))

			delete(data["credentialSubject"].(map[string]interface{})["attachment1"].(map[string]interface{}), field) //nolint
			srv := oidc4vp.NewAttachmentService(nil)
			att, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}},
				map[string]string{
					"doc1": "data:application/json;base64,aGVsbG8gd29ybGQh",
				})

			assert.NoError(t, err)
			assert.Contains(t, att[0].Error, fmt.Sprintf("attachment %s field is required", field))
		})
	}

	t.Run("unsupported algo", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEvidenceAttachment), &data))

		att := data["credentialSubject"].(map[string]interface{})["attachment1"].(map[string]interface{}) //nolint
		att["hash-alg"] = "Murmur3-NOT-SUPPORTED"

		srv := oidc4vp.NewAttachmentService(nil)
		attRes, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}},
			map[string]string{
				"doc1": "data:application/json;base64,aGVsbG8gd29ybGQh",
			})

		assert.NoError(t, err)
		assert.Contains(t, attRes[0].Error, "unsupported hash algorithm: Murmur3-NOT-SUPPORTED")
	})
}
