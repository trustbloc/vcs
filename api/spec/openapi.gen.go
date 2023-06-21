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
	"AP//IPplQg3SAAA=",
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
