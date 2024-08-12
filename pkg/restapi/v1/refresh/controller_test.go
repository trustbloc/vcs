package refresh

const (
	orgID          = "orgID1"
	profileID      = "testID"
	profileVersion = "v1.0"
)

//
//func TestGetGetRefreshedCredential(t *testing.T) {
//	t.Run("success", func(t *testing.T) {
//		cfg := &Controller{}
//
//		reqBody := GetRefreshedCredentialReq{
//			VerifiablePresentation: nil,
//		}
//		req, err := json.Marshal(reqBody)
//		assert.NoError(t, err)
//
//		c := echoContext(withRequestBody(req))
//
//		err = cfg.GetRefreshedCredential(c, profileID, profileVersion,
//			GetRefreshedCredentialParams{})
//		assert.NoError(t, err)
//	})
//}
//
//type options struct {
//	tenantID       string
//	requestBody    []byte
//	responseWriter http.ResponseWriter
//}
//
//type contextOpt func(*options)
//
//func withRequestBody(body []byte) contextOpt {
//	return func(o *options) {
//		o.requestBody = body
//	}
//}
//
//func withRecorder(w http.ResponseWriter) contextOpt {
//	return func(o *options) {
//		o.responseWriter = w
//	}
//}
//
//func echoContext(opts ...contextOpt) echo.Context {
//	o := &options{
//		tenantID:       orgID,
//		responseWriter: httptest.NewRecorder(),
//	}
//
//	for _, fn := range opts {
//		fn(o)
//	}
//
//	e := echo.New()
//
//	var body io.Reader = http.NoBody
//
//	if o.requestBody != nil {
//		body = bytes.NewReader(o.requestBody)
//	}
//
//	req := httptest.NewRequest(http.MethodPost, "/", body)
//	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
//
//	if o.tenantID != "" {
//		req.Header.Set("X-Tenant-ID", o.tenantID)
//	}
//
//	return e.NewContext(req, o.responseWriter)
//}
