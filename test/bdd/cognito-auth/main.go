package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"os"
)

var logger = log.New("cognito-auth")

const (
	addressPattern = ":%s"
)

type Service struct {
	ClientID        string
	ClientSecret    string
	CognitoEndpoint string

	cognitoClient cognitoClient
}

type cognitoClient interface {
	InitiateAuth(
		ctx context.Context,
		params *cip.InitiateAuthInput,
		optFns ...func(options *cip.Options),
	) (*cip.InitiateAuthOutput, error)
}

type GetTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int32  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

func prepareResolver(endpoint string, reg string) aws.EndpointResolverWithOptionsFunc {
	return func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if endpoint != "" && service == cip.ServiceID && region == reg {
			return aws.Endpoint{
				URL:           endpoint,
				SigningRegion: reg,
			}, nil
		}

		return aws.Endpoint{SigningRegion: reg}, &aws.EndpointNotFoundError{}
	}
}

func (s *Service) token(w http.ResponseWriter, req *http.Request) {

	username, password, ok := req.BasicAuth()

	if ok {
		// AuthStyleInHeader
		var err error

		// when used with OAuth2, both clientID and secret must be URL encoded first with url.QueryEscape
		username, err = url.QueryUnescape(username)
		if err != nil {
			writeResponseStatusHeader(w, http.StatusBadRequest, "username not provided")
			return
		}

		password, err = url.QueryUnescape(password)
		if err != nil {
			writeResponseStatusHeader(w, http.StatusBadRequest, "password not provided")
			return
		}
	} else {
		writeResponseStatusHeader(w, http.StatusBadRequest, "invalid credential")
		return
	}

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	input := &cip.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: aws.String(s.ClientID),
		AuthParameters: map[string]string{
			"USERNAME":    username,
			"PASSWORD":    password,
			"SECRET_HASH": computeSecretHash(username, s.ClientID, s.ClientSecret),
		},
	}

	output, err := s.cognitoClient.InitiateAuth(req.Context(), input)
	if err != nil {
		logger.Error("initiate auth", zap.Error(err))
		writeResponseStatusHeader(w, http.StatusInternalServerError, fmt.Sprintf("initiate auth: %v", err))
		return
	}

	if output.AuthenticationResult == nil {
		logger.Error("authentication result from cognito is nil")
		writeResponseStatusHeader(w, http.StatusInternalServerError, "authentication result from cognito is nil")
		return
	}

	gtr := &GetTokenResponse{
		AccessToken:  lo.FromPtr(output.AuthenticationResult.AccessToken),
		ExpiresIn:    output.AuthenticationResult.ExpiresIn,
		IDToken:      lo.FromPtr(output.AuthenticationResult.IdToken),
		RefreshToken: lo.FromPtr(output.AuthenticationResult.RefreshToken),
		TokenType:    lo.FromPtr(output.AuthenticationResult.TokenType),
	}

	writeJsonResponse(w, http.StatusOK, gtr)

}

func writeResponseStatusHeader(w http.ResponseWriter, code int, message string) {
	resp := make(map[string]string)
	resp["message"] = message

	writeJsonResponse(w, code, resp)
}

func writeJsonResponse(w http.ResponseWriter, code int, resp interface{}) {
	w.Header().Add(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
	w.WriteHeader(code)

	enc := json.NewEncoder(w)
	enc.Encode(resp)
}

func computeSecretHash(username, clientID, clientSecret string) string {
	// Base64 ( HMAC_SHA256 ( "Client Secret Key", "Username" + "Client Id" ) )
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func main() {
	clientID := os.Getenv("COGNITO_CLIENT_ID")
	if clientID == "" {
		panic("clientID to be passed as 'COGNITO_CLIENT_ID' ENV variable")
	}

	clientSecret := os.Getenv("COGNITO_CLIENT_SECRET")
	if clientSecret == "" {
		panic("clientSecret to be passed as 'COGNITO_CLIENT_SECRET' ENV variable")
	}

	cognitoEndpoint := os.Getenv("COGNITO_ENDPOINT")
	if cognitoEndpoint == "" {
		panic("cognitoEndpoint to be passed as 'COGNITO_ENDPOINT' ENV variable")
	}

	awsRegion := os.Getenv("AWS_REGION")
	if cognitoEndpoint == "" {
		panic("awsRegion to be passed as 'AWS_REGION' ENV variable")
	}

	hostURL := os.Getenv("HOST_URL")
	if hostURL == "" {
		panic("hostURL to be passed as 'HOST_URL' ENV variable")
	}

	config, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithEndpointResolverWithOptions(prepareResolver(cognitoEndpoint, awsRegion)))
	if err != nil {
		panic("error while preparing cognito aws config")
	}

	service := &Service{
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		CognitoEndpoint: cognitoEndpoint,
		cognitoClient:   cip.NewFromConfig(config),
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/cognito/oauth2/token", service.token).Methods(http.MethodPost)

	if err := http.ListenAndServe(hostURL, router); err != nil {
		logger.Fatal("webhook server start error", log.WithError(err))
	}
}
