package trustregistry

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	util "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"
)

const (
	walletAttestationVCType = "WalletAttestationCredential"
)

func TestService_ValidateVerifier(t *testing.T) {
	now := time.Now()
	handler := echo.New()

	srv := httptest.NewServer(handler)
	defer srv.Close()

	type fields struct {
		url string
	}
	type args struct {
		verifierDID                string
		getPresentationCredentials func(t *testing.T, now time.Time) []*verifiable.Credential
	}
	tests := []struct {
		name               string
		addTestCaseHandler func(t *testing.T, e *echo.Echo)
		fields             fields
		args               args
		wantErr            bool
		errContains        string
	}{
		{
			name: "Success",
			addTestCaseHandler: func(t *testing.T, e *echo.Echo) {
				e.Add(http.MethodPost, "/testcase1", func(c echo.Context) error {
					var got *VerifierValidationConfig
					assert.NoError(t, c.Bind(&got))

					expected := &VerifierValidationConfig{
						VerifierDID: "did:oin:abc",
						Metadata:    getDefaultMetadata(t, now),
					}

					assert.Equal(t, expected, got)

					return c.JSON(http.StatusOK, map[string]bool{"allowed": true})
				})
			},
			fields: fields{
				url: srv.URL + "/testcase1",
			},
			args: args{
				verifierDID:                "did:oin:abc",
				getPresentationCredentials: getDefaultCredentials,
			},
			wantErr: false,
		},
		{
			name:               "httpClient.Post error",
			addTestCaseHandler: func(t *testing.T, e *echo.Echo) {},
			fields: fields{
				url: "abcd",
			},
			args: args{
				verifierDID:                "did:oin:abc",
				getPresentationCredentials: getDefaultCredentials,
			},
			wantErr:     true,
			errContains: "send request:",
		},
		{
			name: "Unexpected status code error",
			addTestCaseHandler: func(t *testing.T, e *echo.Echo) {
				e.Add(http.MethodPost, "/testcase3", func(c echo.Context) error {
					return c.NoContent(http.StatusForbidden)
				})
			},
			fields: fields{
				url: srv.URL + "/testcase3",
			},
			args: args{
				verifierDID:                "did:oin:abc",
				getPresentationCredentials: getDefaultCredentials,
			},
			wantErr:     true,
			errContains: "unexpected status code: 403",
		},
		{
			name: "Read Response error",
			addTestCaseHandler: func(t *testing.T, e *echo.Echo) {
				e.Add(http.MethodPost, "/testcase4", func(c echo.Context) error {
					return c.NoContent(http.StatusOK)
				})
			},
			fields: fields{
				url: srv.URL + "/testcase4",
			},
			args: args{
				verifierDID:                "did:oin:abc",
				getPresentationCredentials: getDefaultCredentials,
			},
			wantErr:     true,
			errContains: "read response:",
		},
		{
			name: "Interaction restricted error",
			addTestCaseHandler: func(t *testing.T, e *echo.Echo) {
				e.Add(http.MethodPost, "/testcase5", func(c echo.Context) error {
					return c.JSON(http.StatusOK, map[string]bool{"allowed": false})
				})
			},
			fields: fields{
				url: srv.URL + "/testcase5",
			},
			args: args{
				verifierDID:                "did:oin:abc",
				getPresentationCredentials: getDefaultCredentials,
			},
			wantErr:     true,
			errContains: "interaction restricted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.addTestCaseHandler(t, handler)

			s := &Service{
				httpClient: http.DefaultClient,
			}

			err := s.ValidateVerifier(tt.fields.url, tt.args.verifierDID, tt.args.getPresentationCredentials(t, now))
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				assert.ErrorContains(t, err, tt.errContains)
			}
		})
	}
}

func getRequestedCredential(t *testing.T, now time.Time) *verifiable.Credential {
	t.Helper()

	vcContent := verifiable.CredentialContents{
		ID: "credentialID1",
		Types: []string{
			"VerifiableCredential",
		},
		Issuer:  &verifiable.Issuer{ID: "issuerID1"},
		Issued:  util.NewTime(now),
		Expired: util.NewTime(now.Add(time.Hour)),
	}

	credential, err := verifiable.CreateCredential(vcContent, nil)
	assert.NoError(t, err)

	return credential
}

func getAttestationCredential(t *testing.T, now time.Time) *verifiable.Credential {
	t.Helper()

	attestationVCContent := verifiable.CredentialContents{
		ID: "credentialID2",
		Types: []string{
			walletAttestationVCType,
		},
		Issuer:  &verifiable.Issuer{ID: "issuerID2"},
		Issued:  util.NewTime(now),
		Expired: util.NewTime(now.Add(time.Hour)),
	}

	credential, err := verifiable.CreateCredential(attestationVCContent, nil)
	assert.NoError(t, err)

	return credential
}

func getDefaultCredentials(t *testing.T, now time.Time) []*verifiable.Credential {
	t.Helper()

	return []*verifiable.Credential{getRequestedCredential(t, now), getAttestationCredential(t, now)}
}

func getDefaultMetadata(t *testing.T, now time.Time) []*CredentialMetadata {
	t.Helper()

	return []*CredentialMetadata{
		{
			CredentialID: "credentialID1",
			Types: []string{
				"VerifiableCredential",
			},
			Issuer:  "issuerID1",
			Issued:  now.Format(time.RFC3339Nano),
			Expired: now.Add(time.Hour).Format(time.RFC3339Nano),
		},
		{
			CredentialID: "credentialID2",
			Types: []string{
				walletAttestationVCType,
			},
			Issuer:  "issuerID2",
			Issued:  now.Format(time.RFC3339Nano),
			Expired: now.Add(time.Hour).Format(time.RFC3339Nano),
		},
	}
}
