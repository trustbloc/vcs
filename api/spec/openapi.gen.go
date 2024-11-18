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
	"/x0AAP//9Uh+Rmk4AQA=",
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
