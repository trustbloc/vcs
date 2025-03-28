// Package spec provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package spec

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	externalRef0 "github.com/trustbloc/vcs/pkg/restapi/v1/common"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
	"P3589/H/BwAA///N/dW37k8BAA==",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	for rawPath, rawFunc := range externalRef0.PathToRawSpec(path.Join(path.Dir(pathToFile), "./common.yaml")) {
		if _, ok := res[rawPath]; ok {
			// it is not possible to compare functions in golang, so always overwrite the old value
		}
		res[rawPath] = rawFunc
	}
	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
