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
	"AAA=",
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
