/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package attributeutil

import (
	"encoding/json"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.opentelemetry.io/otel/attribute"
)

// JSON returns attribute with the value marshaled to JSON. Value can be redacted using WithRedacted option.
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

	for _, path := range op.redacted {
		if gjson.GetBytes(b, path).Exists() {
			b, _ = sjson.SetBytes(b, path, "[REDACTED]")
		}
	}

	return attribute.KeyValue{
		Key:   attribute.Key(key),
		Value: attribute.StringValue(string(b)),
	}
}

// FormParams returns attribute with value represented as form params. Value can be redacted using WithRedacted option.
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

// WithRedacted returns option that replaces value with [REDACTED] for the given key. In case of JSON attribute, key is
// a path to the value to be redacted. Refer to https://github.com/tidwall/gjson/blob/master/SYNTAX.md for path syntax.
func WithRedacted(key string) Opt {
	return func(o *options) {
		o.redacted = append(o.redacted, key)
	}
}
