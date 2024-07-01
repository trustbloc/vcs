package oidc4vp_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

var (
	//go:embed testdata/university_degree_embedded_attachment.jsonld
	sampleVCWithEmbeddedAttachment string
)

func TestAttachment(t *testing.T) {
	t.Run("no attachment in credential", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCJsonLD), &data))

		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.PrepareAttachments(context.TODO(), []*verifiable.Subject{{CustomFields: data}})
		assert.NoError(t, err)
		assert.Empty(t, resp)
	})

	t.Run("with embedded attachment", func(t *testing.T) {
		var data map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(sampleVCWithEmbeddedAttachment), &data))

		srv := oidc4vp.NewAttachmentService(nil)

		resp, err := srv.PrepareAttachments(context.TODO(), []*verifiable.Subject{{CustomFields: data}})
		assert.NoError(t, err)
		assert.Len(t, resp, 1)

		attachment := resp[0]
		assert.EqualValues(t, []interface{}{"EmbeddedAttachment"}, attachment["type"])
		assert.EqualValues(t, "base64content", attachment["uri"])
		assert.Nil(t, attachment["error"])
		assert.EqualValues(t, "5d41402abc4b2a76b9719d911017c592", attachment["hash"])
	})
}
