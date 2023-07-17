package oidc4ci_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestRegex(t *testing.T) {
	testCases := []struct {
		Input     string
		Version   string
		ProfileID string
	}{
		{
			Input:     "https://api-gateway.trustbloc.local:5566/issuer/bank_issuer/v1.0",
			Version:   "v1.0",
			ProfileID: "bank_issuer",
		},
		{
			Input:     "https://api-gateway.trustbloc.local:5566/issuer/some-issuer/latest",
			Version:   "latest",
			ProfileID: "some-issuer",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			rg := regexp.MustCompile(oidc4ci.WalletInitFlowClaimRegex)
			matches := rg.FindStringSubmatch(testCase.Input)
			profileID, profileVersion := matches[2], matches[3]

			assert.Equal(t, testCase.ProfileID, profileID)
			assert.Equal(t, testCase.Version, profileVersion)
		})
	}
}
