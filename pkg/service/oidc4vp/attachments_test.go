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

	//go:embed testdata/university_degree_with_attachments.jsonld
	sampleVCWitAttachments string
)

func TestAttachment(t *testing.T) {
	t.Run("no attachment in credential", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCJsonLD), &data))

		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}})
		assert.NoError(t, err)
		assert.Empty(t, resp)
	})

	t.Run("with embedded attachment", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEmbeddedAttachment), &data))

		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}})
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, []interface{}{"EmbeddedAttachment"}, attachment["type"])
		assert.EqualValues(t, "base64content", attachment["uri"])
		assert.Nil(t, attachment["error"])
		assert.EqualValues(t, "5d41402abc4b2a76b9719d911017c592", attachment["hash"])
	})

	t.Run("with remote attachment err", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithRemoteAttachment), &data))

		mockHttp := NewMockHttpClient(gomock.NewController(t))
		srv := oidc4vp.NewAttachmentService(mockHttp)

		mockHttp.EXPECT().Do(gomock.Any()).
			DoAndReturn(func(request *http.Request) (*http.Response, error) {
				assert.EqualValues(t, "https://someurl.local", request.URL.String())
				assert.EqualValues(t, "GET", request.Method)

				return nil, errors.New("connection failed")
			})

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}})
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, []interface{}{"RemoteAttachment"}, attachment["type"])
		assert.EqualValues(t, "https://someurl.local", attachment["uri"])
		assert.EqualValues(t, "failed to handle remote attachment: failed to fetch url: connection failed",
			attachment["error"])
	})

	t.Run("with remote attachment invalid status", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithRemoteAttachment), &data))

		mockHttp := NewMockHttpClient(gomock.NewController(t))
		srv := oidc4vp.NewAttachmentService(mockHttp)

		mockHttp.EXPECT().Do(gomock.Any()).
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

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}})
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, []interface{}{"RemoteAttachment"}, attachment["type"])
		assert.EqualValues(t, "https://someurl.local", attachment["uri"])
		assert.EqualValues(t, "failed to handle remote attachment: unexpected status code: 404 and body file not found",
			attachment["error"])
	})

	t.Run("with embedded attachment as string type", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEmbeddedAttachment), &data))

		data["credentialSubject"].(map[string]interface{})["attachment1"].(map[string]interface{})["type"] = "EmbeddedAttachment" //nolint
		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}})
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, "EmbeddedAttachment", attachment["type"])
		assert.EqualValues(t, "base64content", attachment["uri"])
		assert.Nil(t, attachment["error"])
		assert.EqualValues(t, "5d41402abc4b2a76b9719d911017c592", attachment["hash"])
	})

	t.Run("with embedded attachment as string arr", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEmbeddedAttachment), &data))

		data["credentialSubject"].(map[string]interface{})["attachment1"].(map[string]interface{})["type"] = []string{"EmbeddedAttachment"} //nolint
		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}})
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, []string{"EmbeddedAttachment"}, attachment["type"])
		assert.EqualValues(t, "base64content", attachment["uri"])
		assert.Nil(t, attachment["error"])
		assert.EqualValues(t, "5d41402abc4b2a76b9719d911017c592", attachment["hash"])
	})

	t.Run("multiple attachments", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWitAttachments), &data))

		mockHttp := NewMockHttpClient(gomock.NewController(t))
		srv := oidc4vp.NewAttachmentService(mockHttp)

		var mut sync.Mutex
		urlsCalled := []string{}

		mockHttp.EXPECT().Do(gomock.Any()).
			DoAndReturn(func(request *http.Request) (*http.Response, error) {
				mut.Lock()
				urlsCalled = append(urlsCalled, request.URL.String())
				defer mut.Unlock()
				assert.EqualValues(t, "GET", request.Method)

				return &http.Response{
					Body: io.NopCloser(bytes.NewBuffer([]byte(
						fmt.Sprintf("base64content-%s", request.URL.String()),
					))),
					StatusCode: http.StatusOK,
				}, nil
			}).Times(2)

		resp, err := srv.GetAttachments(context.TODO(), []verifiable.Subject{{CustomFields: data}})
		assert.NoError(t, err)
		assert.Len(t, resp, 3)

		sort.Strings(urlsCalled)
		assert.EqualValues(t, []string{"https://localhost/cat.png", "https://localhost/photo.png"}, urlsCalled)

		sort.Slice(resp, func(i, j int) bool {
			return resp[i]["id"].(string) < resp[j]["id"].(string)
		})

		attachment := resp[1]
		assert.EqualValues(t, "doc12", attachment["id"])
		assert.EqualValues(t, []interface{}{"EmbeddedAttachment"}, attachment["type"])
		assert.EqualValues(t, "base64content", attachment["uri"])
		assert.Nil(t, attachment["error"])
		assert.EqualValues(t, "5d41402abc4b2a76b9719d911017c592", attachment["hash"])

		attachment = resp[0]
		assert.EqualValues(t, "doc1", attachment["id"])
		assert.EqualValues(t, []interface{}{"RemoteAttachment"}, attachment["type"])
		assert.EqualValues(t, "YmFzZTY0Y29udGVudC1odHRwczovL2xvY2FsaG9zdC9jYXQucG5n", attachment["uri"])
		assert.Nil(t, attachment["error"])
		assert.EqualValues(t, "abcd", attachment["hash"])

		attachment = resp[2]
		assert.EqualValues(t, "doc445", attachment["id"])
		assert.EqualValues(t, []interface{}{"RemoteAttachment"}, attachment["type"])
		assert.EqualValues(t, "YmFzZTY0Y29udGVudC1odHRwczovL2xvY2FsaG9zdC9waG90by5wbmc=", attachment["uri"])
		assert.Nil(t, attachment["error"])
		assert.EqualValues(t, "xyz", attachment["hash"])
	})
}
