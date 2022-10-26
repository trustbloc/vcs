/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func sendInternal[T any, V any](
	ctx context.Context,
	client httpClient,
	method string,
	url string,
	request *T,
) (*V, error) {
	var buf bytes.Buffer

	if request != nil {
		if reqMarshalErr := json.NewEncoder(&buf).Encode(request); reqMarshalErr != nil {
			return nil, reqMarshalErr
		}
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		method,
		url,
		&buf,
	)

	if err != nil {
		return nil, err
	}

	resp, httpErr := client.Do(httpReq)

	if httpErr != nil {
		return nil, httpErr
	}

	var body []byte

	if resp.Body != nil {
		b, bodyErr := io.ReadAll(resp.Body)

		if bodyErr != nil {
			return nil, bodyErr
		}

		body = b
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %v with body %v",
			resp.StatusCode, string(body))
	}

	var final V

	if unmarshalErr := json.Unmarshal(body, &final); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return &final, nil
}
