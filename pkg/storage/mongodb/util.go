/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodb

import (
	"encoding/json"

	"github.com/trustbloc/vcs/internal/utils"
)

func StructureToMap(obj interface{}) (map[string]interface{}, error) {
	return utils.StructureToMap(obj)
}

func MapToStructure(in map[string]interface{}, out interface{}) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, out)
}
