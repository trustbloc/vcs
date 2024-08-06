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
	"u093/z8AAP//lFHkfeMyAQA=",
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
