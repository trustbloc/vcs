package issuecredential_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func TestToDTO(t *testing.T) {
	det := issuecredential.AuthorizationDetails{
		CredentialDefinition: &issuecredential.CredentialDefinition{
			Context: []string{"a", "b"},
			Type:    []string{"c", "d"},
		},
	}

	resp := det.ToDTO()

	assert.Equal(t, []string{"a", "b"}, *resp.CredentialDefinition.Context)
	assert.Equal(t, []string{"c", "d"}, resp.CredentialDefinition.Type)
}
