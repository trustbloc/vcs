/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package attributeutil

import (
	"encoding/json"
	"strings"

	"go.opentelemetry.io/otel/attribute"
)

func JSON(key string, value interface{}, opts ...Opt) attribute.KeyValue {
	op := &options{}

	for _, opt := range opts {
		opt(op)
	}

	b, err := json.Marshal(value)
	if err != nil {
		return attribute.KeyValue{
			Key:   attribute.Key(key),
			Value: attribute.Value{},
		}
	}

	if len(op.redacted) > 0 {
		var m map[string]interface{}

		_ = json.Unmarshal(b, &m)

		for _, k := range op.redacted {
			m[k] = "[REDACTED]"
		}

		b, _ = json.Marshal(m)
	}

	return attribute.KeyValue{
		Key:   attribute.Key(key),
		Value: attribute.StringValue(string(b)),
	}
}

func FormParams(key string, params map[string][]string, opts ...Opt) attribute.KeyValue {
	op := &options{}

	for _, opt := range opts {
		opt(op)
	}

	var buf strings.Builder

	for k, v := range params {
		if buf.Len() > 0 {
			buf.WriteByte('&')
		}

		for _, r := range op.redacted {
			if r == k {
				v = []string{"[REDACTED]"}
				break
			}
		}

		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(strings.Join(v, "&"))
	}

	return attribute.KeyValue{
		Key:   attribute.Key(key),
		Value: attribute.StringValue(buf.String()),
	}
}

type options struct {
	redacted []string
}

type Opt func(*options)

func WithRedacted(key string) Opt {
	return func(o *options) {
		o.redacted = append(o.redacted, key)
	}
}
