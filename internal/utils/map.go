/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import "encoding/json"

func ExtractKeys(prefix string, m map[string]interface{}) []string {
	var keys []string
	for k, v := range m {
		fullKey := prefix + "." + k
		keys = append(keys, fullKey)

		switch nestedVal := v.(type) { //nolint:gocritic
		case map[string]interface{}:
			subKeys := ExtractKeys(fullKey, nestedVal)
			keys = append(keys, subKeys...)
		}
	}
	return keys
}

func StructureToMap(obj interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}

	err = json.Unmarshal(b, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
