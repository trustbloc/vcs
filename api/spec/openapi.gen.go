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
	"/wEAAP//8ktp8LUGAQA=",
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
