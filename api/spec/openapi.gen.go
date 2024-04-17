// Package spec provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.11.0 DO NOT EDIT.
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
	"AAD//7BMZw0tHwEA",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
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
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	pathPrefix := path.Dir(pathToFile)

	for rawPath, rawFunc := range externalRef0.PathToRawSpec(path.Join(pathPrefix, "./common.yaml")) {
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
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
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
