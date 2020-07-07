/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	commhttp "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"
)

const (
	logSpecEndpoint = "/logspec"

	invalidLogSpec = `Invalid log spec. It needs to be in the following format: ` +
		`ModuleName1=Level1:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel
Valid log levels: critical,error,warn,info,debug
Error: %s`

	multipleDefaultValues = "multiple default values found"

	getLogSpecPrepareErrMsg = "Failure while preparing log level response: %s."
)

// Handler represents an HTTP handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// StringBuilder represents a type that can build up a string to be used as the response for a get log spec call.
type StringBuilder interface {
	Write(p []byte) (int, error)
	String() string
	Reset()
}

type moduleLevelPair struct {
	module   string
	logLevel log.Level
}

type logSpec struct {
	Spec string `json:"spec"`
}

// GetRESTHandlers gets all controller API handlers available for this service
func GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(logSpecEndpoint, http.MethodPut, logSpecPutHandler),
		support.NewHTTPHandler(logSpecEndpoint, http.MethodGet, logSpecGetHandler),
	}
}

// Change Log Specification swagger:route PUT /logspec changeLogSpecReq
//
// Changes the current log specification.
// Format: ModuleName1=Level1:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel
// Valid log levels: critical,error,warn,info,debug
//
// Note that this will not work properly if a module name contains an '=' character.
//
// Responses:
//    default: genericError
//        200: emptyRes
func logSpecPutHandler(rw http.ResponseWriter, req *http.Request) {
	changeLogSpec(rw, req)
}

// Get Current Log Specification swagger:route GET /logspec getLogSpecReq
//
// Gets the current log specification.
// Format: ModuleName1=Level1:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel
//
// Responses:
//    default: emptyRes
//        200: getLogSpecRes
func logSpecGetHandler(rw http.ResponseWriter, _ *http.Request) {
	getLogSpec(rw, &strings.Builder{})
}

func changeLogSpec(rw http.ResponseWriter, req *http.Request) {
	var incomingLogSpec logSpec

	err := json.NewDecoder(req.Body).Decode(&incomingLogSpec)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidLogSpec, err))
		return
	}

	logLevelByModule := strings.Split(incomingLogSpec.Spec, ":")

	defaultLogLevel := log.Level(-1)

	var moduleLevelPairs []moduleLevelPair

	for _, logLevelByModulePart := range logLevelByModule {
		if strings.Contains(logLevelByModulePart, "=") {
			moduleAndLevelPair := strings.Split(logLevelByModulePart, "=")

			logLevel, errParse := log.ParseLevel(moduleAndLevelPair[1])
			if errParse != nil {
				commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidLogSpec, errParse))
				return
			}

			moduleLevelPairs = append(moduleLevelPairs,
				moduleLevelPair{moduleAndLevelPair[0], logLevel})
		} else {
			if defaultLogLevel != -1 {
				// The given log spec is formatted incorrectly; it contains multiple default values.
				commhttp.WriteErrorResponse(rw, http.StatusBadRequest,
					fmt.Sprintf(invalidLogSpec, multipleDefaultValues))
				return
			}
			var errParse error

			defaultLogLevel, errParse = log.ParseLevel(logLevelByModulePart)
			if errParse != nil {
				commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidLogSpec, errParse))
				return
			}
		}
	}

	if defaultLogLevel != -1 {
		log.SetLevel("", defaultLogLevel)
	}

	for _, moduleLevelPair := range moduleLevelPairs {
		log.SetLevel(moduleLevelPair.module, moduleLevelPair.logLevel)
	}
}

func getLogSpec(rw http.ResponseWriter, response StringBuilder) {
	logLevels := log.GetAllLevels()

	var defaultDebugLevel string

	for module, level := range logLevels {
		if module == "" {
			defaultDebugLevel = log.ParseString(level)
		} else {
			_, err := response.Write([]byte(module + "=" + log.ParseString(level) + ":"))
			if err != nil {
				commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(getLogSpecPrepareErrMsg, err))
				return
			}
		}
	}

	_, err := response.Write([]byte(defaultDebugLevel))
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(getLogSpecPrepareErrMsg, err))
		return
	}

	commhttp.WriteResponse(rw, logSpec{Spec: response.String()})
}
