/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// PrepareDataForBSONStorage takes the given value and converts it to the type expected by the MongoDB driver for
// inserting documents. The value must be a struct with exported fields and proper json tags or a map. To use the
// MongoDB primary key (_id), you must have an _id field in either the struct or map. Alternatively, add it to the
// map returned by this function. If no _id field is set, then MongoDB will generate one for you.
func PrepareDataForBSONStorage(value interface{}) (map[string]interface{}, error) {
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	return convertMarshalledValueToMap(valueBytes)
}

func convertMarshalledValueToMap(valueBytes []byte) (map[string]interface{}, error) {
	var unmarshalledValue map[string]interface{}

	jsonDecoder := json.NewDecoder(bytes.NewReader(valueBytes))
	jsonDecoder.UseNumber()

	err := jsonDecoder.Decode(&unmarshalledValue)
	if err != nil {
		return nil, err
	}

	escapedMap, err := escapeMapForDocumentDB(unmarshalledValue)
	if err != nil {
		return nil, err
	}

	return escapedMap, nil
}

// escapeMapForDocumentDB recursively travels through the given map and ensures that all keys are safe for DocumentDB.
// All "." characters in keys are replaced with "`" characters.
// If any "`" characters are discovered in keys then an error is returned, since this would cause confusion with the
// scheme described above.
func escapeMapForDocumentDB(unescapedMap map[string]interface{}) (map[string]interface{}, error) {
	escapedMap := make(map[string]interface{})

	for unescapedKey, unescapedValue := range unescapedMap {
		escapedKey, escapedValue, err := escapeKeyValuePair(unescapedKey, unescapedValue)
		if err != nil {
			return nil, err
		}

		escapedMap[escapedKey] = escapedValue
	}

	return escapedMap, nil
}

func escapeKeyValuePair(unescapedKey string, unescapedValue interface{}) (string, interface{},
	error) {
	if strings.Contains(unescapedKey, "`") {
		return "", nil,
			fmt.Errorf(`JSON keys cannot have "`+"`"+`" characters within them. Invalid key: %s`, unescapedKey)
	}

	escapedValue, err := escapeValue(unescapedValue)
	if err != nil {
		return "", nil, err
	}

	return escapeKey(unescapedKey), escapedValue, nil
}

func escapeKey(unescapedKey string) string {
	return strings.ReplaceAll(unescapedKey, ".", "`")
}

func escapeValue(unescapedValue interface{}) (interface{}, error) {
	unescapedValueAsArray, ok := unescapedValue.([]interface{})
	if ok {
		return escapeArray(unescapedValueAsArray)
	}

	unescapedValueAsMap, ok := unescapedValue.(map[string]interface{})
	if ok {
		escapedValue, err := escapeMapForDocumentDB(unescapedValueAsMap)
		if err != nil {
			return nil, err
		}

		return escapedValue, nil
	}

	// In this case, the value is not a nested object or array and so doesn't need escaping.
	return unescapedValue, nil
}

func escapeArray(unescapedArray []interface{}) (interface{}, error) {
	escapedArray := make([]interface{}, len(unescapedArray))

	for i, unescapedValueInUnescapedArray := range unescapedArray {
		escapedValue, err := escapeValue(unescapedValueInUnescapedArray)
		if err != nil {
			return nil, err
		}

		escapedArray[i] = escapedValue
	}

	return escapedArray, nil
}
