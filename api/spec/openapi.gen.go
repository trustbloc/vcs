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
